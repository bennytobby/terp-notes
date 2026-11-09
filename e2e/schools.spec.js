// Multi-school: UMD and UMBC students each see only their own school's notes.
// Needs MongoDB and an S3-compatible store (CI).
const { expect, test } = require("@playwright/test");
const AWS = require("aws-sdk");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb || !process.env.AWS_S3_ENDPOINT, "needs MongoDB and an S3 endpoint");

const umd = { userid: "e2e_umd_student", firstname: "Terry", lastname: "Pin", email: "e2e_umd_student@terpmail.umd.edu" };
const umbc = { userid: "e2e_umbc_student", firstname: "True", lastname: "Grit", email: "e2e_umbc_student@umbc.edu" };

const file = (name, classCode, extra = {}) => ({
    filename: `e2e_school_${name}`, originalName: name, s3Url: "", mimetype: "text/plain", size: 10,
    fileHash: require("crypto").createHash("sha256").update(name + Date.now()).digest("hex"),
    uploadDate: new Date(), uploadedBy: "someone", description: "", classCode, major: classCode.replace(/\d/g, ""),
    semester: "Fall", year: "2026", professor: "", category: "Other", downloadCount: 0, virusScanStatus: "clean", ...extra,
});

test.beforeAll(async () => {
    const s3 = new AWS.S3({
        endpoint: process.env.AWS_S3_ENDPOINT, s3ForcePathStyle: true, signatureVersion: "v4",
        accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, region: "us-east-1",
    });
    await s3.createBucket({ Bucket: process.env.AWS_S3_BUCKET || "terpnotes-e2e" }).promise().catch(() => {});
    await withDb(async (db) => {
        await db.collection("files").deleteMany({ filename: /^e2e_school_/ });
        await db.collection("files").deleteMany({ uploadedBy: umbc.userid });
        await db.collection("noteTexts").deleteMany({ classCode: { $in: ["CMSC447", "CMSC448"] } });
    });
});

test("students only see their own school's notes", async ({ browser }) => {
    const pw = await seedUser(umd);
    await seedUser(umbc, pw);
    const legacy = file("umd-legacy.txt", "CMSC448"); // no school field: counts as UMD
    const theirs = file("umbc-only.txt", "CMSC447", { school: "umbc" });
    const ids = await withDb(async (db) => {
        const a = await db.collection("files").insertOne(legacy);
        const b = await db.collection("files").insertOne(theirs);
        await db.collection("noteTexts").insertMany([
            { fileId: String(a.insertedId), classCode: "CMSC448", originalName: legacy.originalName, filename: legacy.filename, chunks: ["umd notes"] },
            { fileId: String(b.insertedId), classCode: "CMSC447", school: "umbc", originalName: theirs.originalName, filename: theirs.filename, chunks: ["umbc notes"] },
        ]);
        return { a, b };
    });

    // A UMBC student uploads; the file is tagged with their school.
    const b = await browser.newPage();
    await signIn(b, umbc.userid, pw);
    const up = await b.request.post("/upload", {
        multipart: {
            documents: { name: "umbc-upload.txt", mimeType: "text/plain", buffer: Buffer.from(`UMBC upload ${Date.now()}`) },
            classCode: "CMSC447", semester: "Fall", year: "2026", category: "Other",
        },
    });
    expect(await up.text()).toContain("Successfully uploaded 1 file(s) to CMSC447!");
    const uploaded = await withDb((db) => db.collection("files").findOne({ uploadedBy: umbc.userid, originalName: "umbc-upload.txt" }));
    expect(uploaded.school).toBe("umbc");

    await b.goto("/dashboard");
    await expect(b.locator('.file-card[data-name="umbc-only.txt"]')).not.toHaveCount(0);
    await expect(b.locator('.file-card[data-name="umbc-upload.txt"]')).not.toHaveCount(0);
    await expect(b.locator('.file-card[data-name="umd-legacy.txt"]')).toHaveCount(0);
    expect((await b.request.get(`/download/${encodeURIComponent(legacy.filename)}`, { maxRedirects: 0 })).status()).toBe(404);

    // The study buddy only offers the UMBC student their school's courses.
    await b.goto("/study");
    await expect(b.getByLabel("Course").locator("option", { hasText: "CMSC447" })).toHaveCount(1);
    await expect(b.getByLabel("Course").locator("option", { hasText: "CMSC448" })).toHaveCount(0);

    // A UMD student sees the legacy UMD file but none of UMBC's.
    const a = await browser.newPage();
    await signIn(a, umd.userid, pw);
    await expect(a.locator('.file-card[data-name="umd-legacy.txt"]')).not.toHaveCount(0);
    await expect(a.locator('.file-card[data-name="umbc-only.txt"]')).toHaveCount(0);
    await expect(a.locator('.file-card[data-name="umbc-upload.txt"]')).toHaveCount(0);
    expect((await a.request.get(`/download/${encodeURIComponent(theirs.filename)}`, { maxRedirects: 0 })).status()).toBe(404);

    // Registration explains which schools are supported.
    const reg = await a.request.post("/registerSubmit", {
        form: { email: "someone@gmail.com", userid: "x_gmail", first_name: "X", last_name: "Y", password: "Aa1!aaaaaaaa", confirm_pass: "Aa1!aaaaaaaa" },
    });
    expect(await reg.text()).toContain("UMD or UMBC");
});
