// The dashboard: one responsive list with search and filters, edit and delete through the
// page's own dialogs, the old /mobile links redirecting, and direct uploads held to the file-type
// allow-list. Needs MongoDB and an S3-compatible store (CI runs S3Mock).
const { expect, test } = require("@playwright/test");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb || !process.env.AWS_S3_ENDPOINT, "needs MongoDB and an S3 endpoint");

const user = { userid: "e2e_dash", firstname: "Dash", lastname: "Board", email: "e2e_dash@terpmail.umd.edu" };

function note(name, classCode, extra = {}) {
    return {
        filename: `${Date.now()}_${Math.random().toString(36).slice(2)}_${name}`,
        originalName: name,
        classCode,
        major: classCode.replace(/\d.*/, ""),
        professor: "Test Professor",
        semester: "Fall",
        year: "2026",
        category: "Lecture Notes",
        description: `${name} description`,
        uploadedBy: user.userid,
        uploadDate: new Date(),
        size: 1234,
        downloadCount: 0,
        mimetype: "text/plain",
        fileHash: `hash-${name}`,
        school: "umd",
        virusScanStatus: "clean",
        ...extra,
    };
}

test.beforeEach(async () => {
    await withDb(async (db) => {
        await db.collection("files").deleteMany({ uploadedBy: user.userid });
        await db.collection("files").insertMany([
            note("graphs-dash.txt", "CMSC351"),
            note("parsing-dash.txt", "CMSC330", { category: "Study Guide" }),
            note("</script><b>x</b>.txt", "CMSC330"),
        ]);
    });
});

test("search, filters and course chips narrow the list, and the URL keeps them", async ({ page }) => {
    await signIn(page, user.userid, await seedUser(user));
    await page.goto("/dashboard");
    // A file name that looks like markup is shown as text and doesn't break the page.
    await expect(page.locator('.tn-file[data-name="</script><b>x</b>.txt"] .tn-file-name')).toHaveText("</script><b>x</b>.txt");

    await page.getByLabel("Search notes").fill("parsing-dash");
    await expect(page.locator(".tn-file")).toHaveCount(1);
    await expect(page).toHaveURL(/q=parsing-dash/);
    await page.getByRole("button", { name: "Clear filters" }).first().click();

    await page.locator('.tn-file[data-name="graphs-dash.txt"] .tn-chip').click();
    await expect(page.getByLabel("Course")).toHaveValue("CMSC351");
    await expect(page.locator('.tn-file[data-name="parsing-dash.txt"]')).toHaveCount(0);

    await page.goto("/dashboard?course=CMSC330&type=Study%20Guide");
    await expect(page.locator(".tn-file")).toHaveCount(1);
    await expect(page.locator('.tn-file[data-name="parsing-dash.txt"]')).toHaveCount(1);
});

test("an owner edits a note's details and deletes it from the page", async ({ page }) => {
    await signIn(page, user.userid, await seedUser(user));
    await page.goto("/dashboard");
    const row = page.locator('.tn-file[data-name="graphs-dash.txt"]');

    await row.locator("summary").click();
    await row.getByRole("menuitem", { name: "Edit details" }).click();
    await page.getByLabel(/Description/).fill("Week 9: shortest paths");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(row.locator(".tn-file-desc")).toHaveText("Week 9: shortest paths");
    const saved = await withDb((db) => db.collection("files").findOne({ uploadedBy: user.userid, originalName: "graphs-dash.txt" }));
    expect(saved.description).toBe("Week 9: shortest paths");

    await row.locator("summary").click();
    await row.getByRole("menuitem", { name: "Delete" }).click();
    await page.locator("#confirmDialog").getByRole("button", { name: "Delete" }).click();
    await expect(row).toHaveCount(0);
    expect(await withDb((db) => db.collection("files").countDocuments({ uploadedBy: user.userid, originalName: "graphs-dash.txt" }))).toBe(0);
});

test("old /mobile links open the responsive pages", async ({ page }) => {
    await signIn(page, user.userid, await seedUser(user));
    await page.goto("/mobile/dashboard");
    await expect(page).toHaveURL(/\/dashboard$/);
    await page.goto("/mobile/upload");
    await expect(page.getByRole("heading", { name: "Upload notes" })).toBeVisible();
});

test("direct uploads only accept allowed file types", async ({ page }) => {
    await signIn(page, user.userid, await seedUser(user));
    const bad = await page.request.post("/api/get-upload-url", { data: { filename: "tool.exe", filetype: "application/x-msdownload", filesize: 10 } });
    expect(bad.status()).toBe(400);
    expect((await bad.json()).error).toContain("File type not allowed: .exe");
    const ok = await page.request.post("/api/get-upload-url", { data: { filename: "notes.md", filetype: "application/octet-stream", filesize: 10 } });
    expect(ok.status()).toBe(200);
});
