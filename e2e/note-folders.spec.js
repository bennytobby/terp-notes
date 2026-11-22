const { expect, test } = require("@playwright/test");
const { seedUser, signIn, withDb } = require("./helpers");

const owner = { userid: "e2e_folders", email: "e2e_folders@terpmail.umd.edu" };
const classmate = { userid: "e2e_folders_other", email: "e2e_folders_other@terpmail.umd.edu" };

async function seedNote() {
    const note = {
        originalName: "folder-test-notes.txt", filename: `folder-test-${Date.now()}.txt`,
        classCode: "MATH240", school: "umd", mimetype: "text/plain", uploadedBy: owner.userid,
        category: "Lecture Notes", uploadDate: new Date(),
    };
    await withDb(db => db.collection("files").insertOne(note));
    return note;
}

test("folder APIs enforce ownership and current note visibility", async ({ request, playwright, baseURL }) => {
    const other = await playwright.request.newContext({ baseURL });
    try {
        expect((await request.get("/api/folders")).status()).toBe(401);
        for (const [api, user] of [[request, owner], [other, classmate]]) {
            const password = await seedUser(user);
            const login = await api.post("/loginSubmit", { form: { userid: user.userid, password }, maxRedirects: 0 });
            expect(login.headers().location).toBe("/dashboard");
        }
        const created = await request.post("/api/folders", { data: { action: "create", name: "Linear algebra" } });
        expect(created.ok()).toBe(true);
        const { folderId } = await created.json();
        const note = await seedNote();
        const save = { action: "save", folderId, filename: note.filename };
        expect((await other.post("/api/folders", { data: save })).status()).toBe(404);
        expect((await other.get(`/folders?folder=${folderId}`)).status()).toBe(404);
        expect(await (await other.get("/api/folders")).json()).toEqual({ folders: [] });
        expect((await request.post("/api/folders", { data: save })).ok()).toBe(true);
        expect((await request.post("/api/folders", { data: save })).ok()).toBe(true);
        const html = await (await request.get(`/folders?folder=${folderId}`)).text();
        expect(html.match(/>folder-test-notes\.txt</g)).toHaveLength(1);
        await withDb(db => db.collection("files").updateOne({ _id: note._id }, { $set: { school: "umbc" } }));
        expect((await request.post("/api/folders", { data: save })).status()).toBe(404);
        const unavailable = await (await request.get(`/folders?folder=${folderId}`)).text();
        expect(unavailable).toContain("Note unavailable");
        expect(unavailable).not.toContain(note.filename);
        expect((await request.post("/api/folders", { data: { action: "remove", folderId, noteId: String(note._id) } })).ok()).toBe(true);
        expect(await (await request.get(`/folders?folder=${folderId}`)).text()).toContain("This folder is empty");
        const create = await request.post("/api/folders", { data: { action: "create", name: "Final" } });
        const { folderId: finalFolder } = await create.json();
        expect((await request.post("/api/folders", { data: { action: "rename", folderId, name: "Final" } })).status()).toBe(409);
        expect((await request.post("/api/folders", { data: { action: "rename", folderId, name: "Midterm" } })).ok()).toBe(true);
        expect((await request.post("/api/folders", { data: { action: "delete", folderId } })).ok()).toBe(true);
        expect(await (await request.get("/api/folders")).json()).toEqual({ folders: [{ id: finalFolder, name: "Final" }] });
        expect(await withDb(db => db.collection("files").countDocuments({ _id: note._id }))).toBe(1);
    } finally {
        await other.dispose();
    }
});

test("a student saves a note into a new folder and finds it again on a phone", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await withDb(db => db.collection("files").deleteMany({ uploadedBy: owner.userid }));
    const note = await seedNote();
    await signIn(page, owner.userid, await seedUser(owner));
    await page.getByLabel(`More actions for ${note.originalName}`).click();
    await page.getByRole("menuitem", { name: "Save to folder" }).click();
    const dialog = page.getByRole("dialog", { name: "Save to folder" });
    await dialog.getByLabel("New folder name").fill("Midterm");
    await dialog.getByRole("button", { name: "Save note" }).click();
    await expect(dialog.getByRole("status")).toHaveText("Saved to Midterm.");
    await dialog.getByRole("link", { name: "Open saved folders" }).click();
    await expect(page.getByRole("heading", { name: "Midterm" })).toBeVisible();
    await expect(page.getByRole("link", { name: `Download ${note.originalName}` })).toHaveAttribute("href", /\?force=download$/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
    await page.reload();
    await expect(page.getByRole("link", { name: note.originalName, exact: true })).toBeVisible();
    await page.getByRole("button", { name: `Remove ${note.originalName} from folder` }).click();
    await expect(page.getByText("This folder is empty.", { exact: false })).toBeVisible();
});
