// Desktop uploads go straight to S3 and are then confirmed. They must get the same treatment as
// every other note: study buddy index, confidential scan, school. Also checks that every signed-in
// page links to the study buddy, and that imports are held to the upload form's class details.
// Needs MongoDB and an S3-compatible store (CI runs S3Mock and sets AWS_S3_ENDPOINT).
const { expect, test } = require("@playwright/test");
const AWS = require("aws-sdk");
const crypto = require("node:crypto");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb || !process.env.AWS_S3_ENDPOINT, "needs MongoDB and an S3 endpoint");

const s3 = new AWS.S3({
    endpoint: process.env.AWS_S3_ENDPOINT,
    s3ForcePathStyle: true,
    signatureVersion: "v4",
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: "us-east-1",
});
const bucket = process.env.AWS_S3_BUCKET || "terpnotes-e2e";
const user = { userid: "e2e_direct", firstname: "Dee", lastname: "Rect", email: "e2e_direct@terpmail.umd.edu" };

test.beforeAll(async () => {
    await s3.createBucket({ Bucket: bucket }).promise().catch(() => {});
    await withDb(async (db) => {
        await db.collection("files").deleteMany({ uploadedBy: user.userid });
        await db.collection("noteTexts").deleteMany({ classCode: "CMSC216" });
    });
});

/** What the dashboard does: the browser PUTs the file to S3, then confirms it. */
async function directUpload(page, name, text, type = "text/plain") {
    const body = Buffer.isBuffer(text) ? text : Buffer.from(text);
    const s3Key = `${Date.now()}_e2e_${name}`;
    await s3.putObject({ Bucket: bucket, Key: s3Key, Body: body, ContentType: type }).promise();
    const res = await page.request.post("/api/confirm-upload", {
        data: {
            s3Key,
            s3Url: `${process.env.AWS_S3_ENDPOINT}/${bucket}/${s3Key}`,
            filename: name,
            filetype: type,
            filesize: body.length,
            fileHash: crypto.createHash("sha256").update(body).digest("hex"),
            classCode: "CMSC216",
            professor: "Test Professor",
            semester: "Fall",
            year: "2026",
            category: "Lecture Notes",
            description: "e2e direct upload",
        },
    });
    expect(res.ok()).toBeTruthy();
    return res.json();
}

test("a direct upload is indexed for the study buddy, scanned and tagged with the school", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);

    const result = await directUpload(page, "pointers.txt", `Pointers ${Date.now()}\nA pointer stores a memory address. Dereferencing reads the value at that address.`);
    expect(result.success).toBe(true);
    expect(result.held).toBe(false);

    const file = await withDb((db) => db.collection("files").findOne({ uploadedBy: user.userid, originalName: "pointers.txt" }));
    expect(file.school).toBe("umd");
    expect(file.confidentialScan.status).toBe("clean");
    const indexed = await withDb((db) => db.collection("noteTexts").findOne({ fileId: String(file._id) }));
    expect(indexed.chunks.join(" ")).toContain("memory address");

    // And it shows up as a course in the study buddy (old /study links open the panel).
    await page.goto("/study");
    await expect(page.getByLabel("Study Buddy course").locator("option", { hasText: "CMSC216" })).toHaveCount(1);
});

test("a PDF upload is read and indexed (PDF reading must not need native modules)", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);
    const pdf = require("node:fs").readFileSync(require("node:path").join(__dirname, "..", "test", "fixtures", "stack-notes.pdf"));
    const result = await directUpload(page, "stack-notes.pdf", pdf, "application/pdf");
    expect(result.success).toBe(true);
    const file = await withDb((db) => db.collection("files").findOne({ uploadedBy: user.userid, mimetype: "application/pdf" }, { sort: { uploadDate: -1 } }));
    expect(file.confidentialScan.status).toBe("clean");
    const indexed = await withDb((db) => db.collection("noteTexts").findOne({ fileHash: file.fileHash }));
    expect(indexed.chunks.join(" ")).toContain("last-in first-out");
});

test("a direct upload with an ID roster is held for review", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);
    const roster = `Roster ${Date.now()}\nName, UID\nA, 117000001\nB, 117000002\nC, 117000003\nD, 117000004`;
    const result = await directUpload(page, "roster.txt", roster);
    expect(result.held).toBe(true);
    const file = await withDb((db) => db.collection("files").findOne({ uploadedBy: user.userid, originalName: "roster.txt" }));
    expect(file.quarantined).toBe(true);
});

test("the study buddy opens on every signed-in page, and settings holds profile, integrations and AI apps", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);
    const panel = page.getByRole("dialog", { name: "Study Buddy" });
    // Old addresses still work and land on the matching settings tab.
    for (const [old, now] of [["/profile", "/settings"], ["/integrations", "/settings/apps"], ["/ai-access", "/settings/ai"]]) {
        await page.goto(old);
        await expect(page).toHaveURL(new RegExp(`${now}$`));
        await expect(page.getByRole("heading", { level: 1, name: "Settings" })).toBeVisible();
        // The buddy opens over the page instead of navigating away from it.
        await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Study Buddy" }).click();
        await expect(panel).toBeVisible();
        await expect(page).toHaveURL(new RegExp(`${now}$`));
        await panel.getByRole("button", { name: "Close Study Buddy" }).click();
        await expect(panel).toBeHidden();
    }
    await page.getByRole("navigation", { name: "Settings" }).getByRole("link", { name: "Integrations" }).click();
    await expect(page).toHaveURL(/\/settings\/apps$/);

    // The panel stays open, with its chat, when moving to another page.
    await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Study Buddy" }).click();
    await expect(panel).toBeVisible();
    await page.goto("/dashboard");
    await expect(panel).toBeVisible();
    await panel.getByRole("button", { name: "Close Study Buddy" }).click();

    // A link can no longer delete a file: deleting is POST-only.
    expect((await page.request.get("/delete/anything.txt")).status()).toBe(404);
});

test("a student keeps their courses in the sidebar", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);
    const add = page.getByLabel("Add a course to My courses");
    await add.fill("cmsc216");
    await add.press("Enter");
    const link = page.locator('.tn-side-course[data-course-link="CMSC216"]');
    await expect(link).toBeVisible();
    await add.fill("not a course");
    await add.press("Enter");
    await expect(page.locator("#sideAddError")).toHaveText("Use a class code like CMSC330.");
    // It is saved to the account, so it is still there after a reload, and opens that course's notes.
    await page.reload();
    await link.click();
    await expect(page).toHaveURL(/course=CMSC216/);
    await page.getByRole("button", { name: "Remove CMSC216 from My courses" }).click();
    await expect(link).toHaveCount(0);
    expect((await page.request.post("/api/courses/pin", { data: { classCode: "nope!" } })).status()).toBe(400);
});

test("imports need the same class details as an upload, and course look-ups work", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);

    const bad = await page.request.post("/api/integrations/notion/import", {
        data: { sourceId: "x", options: { classCode: "intro", semester: "", year: "", category: "" } },
    });
    expect(bad.status()).toBe(400);
    const body = await bad.json();
    expect(Object.keys(body.fields).sort()).toEqual(["category", "classCode", "professor", "semester", "year"]);

    const suggest = await (await page.request.get("/api/course-suggest?q=cmsc33")).json();
    expect(suggest.courses[0].id).toBe("CMSC330");
    const course = await (await page.request.get("/api/course-suggest/CMSC330")).json();
    expect(course.name).toContain("Programming Languages");
    expect(course.professors.length).toBeGreaterThan(0);
});
