// Confidential-information scanner: high-risk uploads are held for admin review.
// Needs MongoDB and an S3-compatible store (CI runs S3Mock).
const { expect, test } = require("@playwright/test");
const AWS = require("aws-sdk");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb || !process.env.AWS_S3_ENDPOINT, "needs MongoDB and an S3 endpoint");

const uploader = { userid: "e2e_conf_up", firstname: "Ula", lastname: "Up", email: "e2e_conf_up@terpmail.umd.edu" };
const classmate = { userid: "e2e_conf_mate", firstname: "Cam", lastname: "Mate", email: "e2e_conf_mate@terpmail.umd.edu" };
const admin = { userid: "e2e_conf_admin", firstname: "Ada", lastname: "Admin", email: "e2e_conf_admin@terpmail.umd.edu", role: "admin" };

test.beforeAll(async () => {
    const s3 = new AWS.S3({
        endpoint: process.env.AWS_S3_ENDPOINT, s3ForcePathStyle: true, signatureVersion: "v4",
        accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, region: "us-east-1",
    });
    await s3.createBucket({ Bucket: process.env.AWS_S3_BUCKET || "terpnotes-e2e" }).promise().catch(() => {});
    await withDb((db) => db.collection("files").deleteMany({ uploadedBy: uploader.userid }));
});

async function upload(page, name, content) {
    const res = await page.request.post("/upload", {
        multipart: {
            documents: { name, mimeType: "text/plain", buffer: Buffer.from(content) },
            classCode: "CMSC330", semester: "Fall", year: "2026", category: "Other",
        },
    });
    expect(res.status()).toBe(200);
    return res.text();
}

test("a roster is held for review; an answer key is flagged but visible; an admin approves", async ({ browser }) => {
    const pw = await seedUser(uploader);
    await seedUser(classmate, pw);
    await seedUser(admin, pw);

    // Unique content each run so deduplication doesn't reuse an old scan result.
    const run = Date.now();
    const up = await browser.newPage();
    await signIn(up, uploader.userid, pw);
    const roster = `Section 0101 roster ${run}\nName, UID, Grade\nAlice, 117000001, A\nBob, 117000002, B\nCara, 117000003, A-`;
    const html = await upload(up, "roster.txt", roster);
    expect(html).toContain("Successfully uploaded 1 file(s) to CMSC330!");
    expect(html).toContain("hidden from other students until an admin reviews them");
    await upload(up, "midterm-key.txt", `CMSC330 Midterm ${run} - Answer Key\n1. b\n2. d`);

    const held = await withDb((db) => db.collection("files").findOne({ uploadedBy: uploader.userid, originalName: "roster.txt" }));
    expect(held.quarantined).toBe(true);
    expect(held.confidentialScan).toMatchObject({ status: "flagged", level: "high" });
    expect(JSON.stringify(held.confidentialScan)).not.toContain("117000001"); // only masked samples stored
    const key = await withDb((db) => db.collection("files").findOne({ uploadedBy: uploader.userid, originalName: "midterm-key.txt" }));
    expect(key.quarantined).toBe(false);
    expect(key.confidentialScan.level).toBe("medium");

    // The uploader sees their held file, with a badge.
    await up.goto("/dashboard");
    // Cards sit in collapsible course groups, so check they're on the page rather than visible.
    await expect(up.locator('.tn-file[data-name="roster.txt"] .held-for-review')).toHaveCount(1);

    // A classmate can't see or download it, but does see the answer key.
    const mate = await browser.newPage();
    await signIn(mate, classmate.userid, pw);
    await expect(mate.locator('.tn-file[data-name="midterm-key.txt"]')).not.toHaveCount(0);
    await expect(mate.locator('.tn-file[data-name="roster.txt"]')).toHaveCount(0);
    const dl = await mate.request.get(`/download/${encodeURIComponent(held.filename)}`, { maxRedirects: 0 });
    expect(dl.status()).toBe(403);
    expect(await dl.text()).toContain("File Under Review");

    // An admin sees both in the review queue and approves the roster.
    const adm = await browser.newPage();
    await signIn(adm, admin.userid, pw);
    await adm.goto("/admin");
    const card = adm.locator(`.flagged-card[data-file-hash="${held.fileHash}"]`);
    await expect(card).toContainText("List of student IDs");
    await expect(card).toContainText("High: hidden");
    await expect(adm.locator(`.flagged-card[data-file-hash="${key.fileHash}"]`)).toContainText("Medium: visible");
    const review = await adm.request.post("/api/admin/confidential-review", { data: { fileHash: held.fileHash, action: "approve" } });
    expect(review.status()).toBe(200);

    // Non-admins can't use the review endpoint.
    const denied = await mate.request.post("/api/admin/confidential-review", { data: { fileHash: key.fileHash, action: "remove" } });
    expect(denied.status()).toBe(401);

    // Now the classmate sees the approved roster.
    await mate.goto("/dashboard");
    await expect(mate.locator('.tn-file[data-name="roster.txt"]')).not.toHaveCount(0);
});
