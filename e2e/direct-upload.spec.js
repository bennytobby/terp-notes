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

    // And it shows up as a course on the study page.
    await page.goto("/study");
    await expect(page.getByLabel("Course").locator("option", { hasText: "CMSC216" })).toHaveCount(1);
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

test("every signed-in page links to the study buddy, and the study page links back", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);
    for (const path of ["/profile", "/integrations", "/ai-access"]) {
        await page.goto(path);
        await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Study Buddy" })).toBeVisible();
    }
    await page.goto("/study");
    const nav = page.getByRole("navigation", { name: "Main" });
    await expect(nav.getByRole("link", { name: "Study Buddy" })).toHaveAttribute("aria-current", "page");
    await nav.getByRole("link", { name: "Integrations" }).click();
    await expect(page).toHaveURL(/\/integrations$/);
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
