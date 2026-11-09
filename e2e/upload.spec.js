// Uploading a note: stored in S3, recorded in MongoDB, reported as a success, queued for scanning.
// Needs MongoDB and an S3-compatible store (CI runs S3Mock and sets AWS_S3_ENDPOINT).
const { expect, test } = require("@playwright/test");
const AWS = require("aws-sdk");
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
const user = { userid: "e2e_uploader", firstname: "Up", lastname: "Loader", email: "e2e_uploader@terpmail.umd.edu" };

test.beforeAll(async () => {
    await s3.createBucket({ Bucket: bucket }).promise().catch((e) => {
        if (e.code !== "BucketAlreadyOwnedByYou" && e.code !== "BucketAlreadyExists") throw e;
    });
    await withDb((db) => db.collection("files").deleteMany({ uploadedBy: user.userid }));
});

test("a student uploads a note and it is stored, recorded and reported as a success", async ({ page }) => {
    const password = await seedUser(user);
    await signIn(page, user.userid, password);

    const content = `Week 1 notes ${Date.now()}`;
    const res = await page.request.post("/upload", {
        multipart: {
            documents: { name: "week1.txt", mimeType: "text/plain", buffer: Buffer.from(content) },
            classCode: "cmsc131",
            semester: "Fall",
            year: "2026",
            professor: "Test Professor",
            category: "Lecture Notes",
        },
    });
    expect(res.status()).toBe(200);
    const html = await res.text();
    expect(html).toContain("Successfully uploaded 1 file(s) to CMSC131!");
    expect(html).not.toContain("failed to upload");

    const file = await withDb((db) => db.collection("files").findOne({ uploadedBy: user.userid }));
    expect(file).toMatchObject({ originalName: "week1.txt", classCode: "CMSC131", professor: "Test Professor" });
    const object = await s3.getObject({ Bucket: bucket, Key: file.filename }).promise();
    expect(object.Body.toString()).toBe(content);

    // The upload shows on the dashboard.
    await page.goto("/dashboard");
    // Files sit in collapsible course groups, so check the card is on the page.
    await expect(page.locator('.file-card[data-name="week1.txt"]')).not.toHaveCount(0);
});
