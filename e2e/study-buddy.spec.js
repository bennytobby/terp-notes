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

    await page.goto("/dashboard");
    await page.getByRole("link", { name: "Study Buddy" }).click();
    await page.getByLabel("Course").selectOption("CMSC132");
    await page.getByLabel("Your question").fill("How does push work on a stack?");
    await page.getByRole("button", { name: "Ask" }).click();
    const reply = page.locator(".msg.buddy").last();
    await expect(reply).toContainText("AI answer");
    await expect(reply).toContainText("Mock answer based on stacks-and-queues.txt [1].");
    const source = reply.locator(".source a");
    await expect(source).toHaveText("[1] stacks-and-queues.txt");
    await expect(source).toHaveAttribute("href", /^\/download\//);

    await page.getByRole("button", { name: "Quiz me" }).click();
    await expect(page.locator(".msg.buddy").last()).toContainText("mock quiz from stacks-and-queues.txt");

    // Validation and sign-in are enforced by the API.
    expect((await page.request.post("/api/study/ask", { data: { classCode: "nonsense!", question: "hi there" } })).status()).toBe(400);
    const anon = await page.context().browser().newContext();
    expect((await anon.request.post(`${test.info().project.use.baseURL}/api/study/ask`, { data: { classCode: "CMSC132", question: "stack" } })).status()).not.toBe(200);
    await anon.close();
});
