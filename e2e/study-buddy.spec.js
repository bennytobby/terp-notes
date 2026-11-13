// AI study buddy: upload notes, ask a question, get an answer with sources, get a quiz.
// Needs MongoDB and an S3-compatible store (CI); the AI model is e2e/mock-llm.js.
const { expect, test } = require("@playwright/test");
const AWS = require("aws-sdk");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb || !process.env.AWS_S3_ENDPOINT, "needs MongoDB and an S3 endpoint");

const student = { userid: "e2e_study", firstname: "Stu", lastname: "Dee", email: "e2e_study@terpmail.umd.edu" };

test.beforeAll(async () => {
    const s3 = new AWS.S3({
        endpoint: process.env.AWS_S3_ENDPOINT, s3ForcePathStyle: true, signatureVersion: "v4",
        accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, region: "us-east-1",
    });
    await s3.createBucket({ Bucket: process.env.AWS_S3_BUCKET || "terpnotes-e2e" }).promise().catch(() => {});
    await withDb(async (db) => {
        await db.collection("files").deleteMany({ uploadedBy: student.userid });
        await db.collection("noteTexts").deleteMany({ classCode: "CMSC132" });
        await db.collection("studyUsage").deleteMany({ userid: student.userid });
    });
});

test("a student asks the study buddy about uploaded notes and gets a cited answer and a quiz", async ({ page }) => {
    const pw = await seedUser(student);
    await signIn(page, student.userid, pw);
    const notes = `Stacks and queues ${Date.now()}\nA stack is last-in first-out (LIFO). Push adds to the top and pop removes from the top.\nA queue is first-in first-out (FIFO).`;
    const up = await page.request.post("/upload", {
        multipart: {
            documents: { name: "stacks-and-queues.txt", mimeType: "text/plain", buffer: Buffer.from(notes) },
            classCode: "CMSC132", semester: "Fall", year: "2026", category: "Lecture Notes",
        },
    });
    expect(await up.text()).toContain("Successfully uploaded 1 file(s) to CMSC132!");
    const indexed = await withDb((db) => db.collection("noteTexts").findOne({ classCode: "CMSC132", originalName: "stacks-and-queues.txt" }));
    expect(indexed.chunks.join(" ")).toContain("last-in first-out");

    // The buddy is a panel on the page you're already on, not a page of its own.
    await page.goto("/dashboard");
    await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Study Buddy" }).click();
    const panel = page.getByRole("dialog", { name: "Study Buddy" });
    await expect(panel).toBeVisible();
    await expect(page).toHaveURL(/\/dashboard$/);
    await panel.getByLabel("Study Buddy course").selectOption("CMSC132");
    await panel.getByLabel("Your question").fill("How does push work on a stack?");
    await panel.getByRole("button", { name: "Ask", exact: true }).click();
    const reply = page.locator(".msg.buddy").last();
    await expect(reply).toContainText("AI answer");
    await expect(reply).toContainText("Mock answer based on stacks-and-queues.txt");
    const source = reply.locator(".source a");
    await expect(source).toHaveText("[1] stacks-and-queues.txt");
    await expect(source).toHaveAttribute("href", /^\/download\//);

    await panel.getByRole("button", { name: "Quiz me" }).click();
    await expect(page.locator(".msg.buddy").last()).toContainText("mock quiz from stacks-and-queues.txt");

    // Study material from one chosen file: pick it, then ask for a cheat sheet.
    await panel.getByRole("button", { name: "All notes" }).click();
    await panel.getByLabel("stacks-and-queues.txt").check();
    await expect(panel.getByRole("button", { name: "1 file" })).toBeVisible();
    await panel.getByRole("button", { name: "Cheat sheet" }).click();
    const sheet = page.locator(".msg.buddy").last();
    await expect(sheet).toContainText("Cheat sheet");
    await expect(sheet).toContainText("mock cheat sheet from stacks-and-queues.txt");
    await expect(sheet.getByRole("button", { name: "Download" })).toBeVisible();

    // The chat follows the student to other pages.
    await page.goto("/settings");
    await expect(page.getByRole("dialog", { name: "Study Buddy" })).toBeVisible();
    await expect(page.locator(".msg.buddy").last()).toContainText("mock cheat sheet");

    // The row menu hands a file straight to the buddy.
    await page.goto("/dashboard");
    await page.getByRole("button", { name: "Close Study Buddy" }).click();
    const row = page.locator('.tn-file[data-name="stacks-and-queues.txt"]').first();
    await row.locator("summary").click();
    await row.getByRole("menuitem", { name: "Ask Study Buddy" }).click();
    await expect(page.getByRole("dialog", { name: "Study Buddy" })).toBeVisible();
    await expect(page.locator(".tn-buddy-chip")).toContainText("stacks-and-queues.txt");

    // The picker only lists files the student can read.
    const context = await (await page.request.get("/api/study/context?course=CMSC132")).json();
    expect(context.courses).toContain("CMSC132");
    expect(context.files.map((f) => f.name)).toContain("stacks-and-queues.txt");
    expect((await page.request.post("/api/study/ask", { data: { question: "no course or files given" } })).status()).toBe(400);

    // Validation and sign-in are enforced by the API.
    expect((await page.request.post("/api/study/ask", { data: { classCode: "nonsense!", question: "hi there" } })).status()).toBe(400);
    const anon = await page.context().browser().newContext();
    expect((await anon.request.post(`${test.info().project.use.baseURL}/api/study/ask`, { data: { classCode: "CMSC132", question: "stack" } })).status()).not.toBe(200);
    await anon.close();
});
