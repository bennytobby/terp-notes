// Professors and TAs: admin invite -> professor accepts -> adds a TA -> course-scoped moderation.
// Needs MongoDB (CI provides it).
const { expect, test } = require("@playwright/test");
const crypto = require("crypto");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb, "needs MongoDB");

const admin = { userid: "e2e_staff_admin", firstname: "Ada", lastname: "Admin", email: "e2e_staff_admin@terpmail.umd.edu", role: "admin" };
const prof = { userid: "e2e_prof", firstname: "Pat", lastname: "Prof", email: "e2e_prof@terpmail.umd.edu" };
const ta = { userid: "e2e_ta", firstname: "Tia", lastname: "Assistant", email: "e2e_ta@terpmail.umd.edu" };
const student = { userid: "e2e_staff_student", firstname: "Sam", lastname: "Student", email: "e2e_staff_student@terpmail.umd.edu" };

function fileDoc(name, classCode, uploadedBy) {
    const hash = crypto.createHash("sha256").update(name + classCode + Date.now()).digest("hex");
    return {
        filename: `e2e_${hash.slice(0, 8)}_${name}`, originalName: name, s3Url: "", mimetype: "text/plain",
        size: 10, fileHash: hash, uploadDate: new Date(), uploadedBy, description: "", classCode,
        major: classCode.replace(/[0-9]/g, ""), semester: "Fall", year: "2026", professor: "", category: "Other",
        downloadCount: 0, virusScanStatus: "clean", quarantined: false,
    };
}

test.beforeAll(async () => {
    await withDb(async (db) => {
        await db.collection("courseStaff").deleteMany({ userid: { $in: [prof.userid, ta.userid] } });
        await db.collection("staffInvites").deleteMany({ email: { $in: [prof.email, student.email] } });
        await db.collection("files").deleteMany({ uploadedBy: { $in: [prof.userid, student.userid] } });
    });
});

test("admin invites a professor, who adds a TA; staff moderate only their course", async ({ browser }) => {
    const pw = await seedUser(admin);
    for (const u of [prof, ta, student]) await seedUser(u, pw);
    const [inCourse, otherCourse, fromProf] = [
        fileDoc("leaked-exam.txt", "CMSC131", student.userid),
        fileDoc("other-course.txt", "CMSC132", student.userid),
        fileDoc("official-slides.txt", "CMSC131", prof.userid),
    ];
    await withDb((db) => db.collection("files").insertMany([inCourse, otherCourse, fromProf]));

    // 1. The admin creates an invite from the admin page.
    const adm = await browser.newPage();
    await signIn(adm, admin.userid, pw);
    await adm.goto("/admin");
    await adm.getByLabel("Professor's email").fill("E2E_PROF@umd.edu"); // umd.edu == terpmail.umd.edu
    await adm.getByLabel("Course code").fill("cmsc 131");
    await adm.getByRole("button", { name: "Create invite" }).click();
    const link = (await adm.locator("#invite-link").textContent()).trim();
    expect(link).toMatch(/\/invite\/[a-f0-9]{64}$/);
    const path = new URL(link).pathname;

    // 2. Someone else signed in can't use it.
    const stu = await browser.newPage();
    await signIn(stu, student.userid, pw);
    await stu.goto(path);
    await stu.getByRole("button", { name: "Accept invite" }).click();
    await expect(stu.getByText("This invite is for e2e_prof@terpmail.umd.edu")).toBeVisible();

    // 3. The professor opens it signed out, signs in, comes back and accepts.
    const pr = await browser.newPage();
    await pr.goto(path);
    await expect(pr.getByRole("heading", { name: "You're invited to teach CMSC131" })).toBeVisible();
    await pr.getByRole("link", { name: "Sign in" }).click();
    await pr.getByLabel("Username").fill(prof.userid);
    await pr.getByLabel("Password").fill(pw);
    await pr.getByRole("button", { name: "Login" }).click();
    await expect(pr).toHaveURL(new RegExp(`${path}$`));
    await pr.getByRole("button", { name: "Accept invite" }).click();
    await expect(pr).toHaveURL(/\/staff$/);
    const course = pr.locator('section.course[data-course="CMSC131"]');
    await expect(course.locator(".role-pill")).toHaveText("Professor");

    // The link is single-use.
    await pr.goto(path);
    await expect(pr.getByText("This invite has already been used.")).toBeVisible();

    // 4. The professor adds a TA by email.
    await pr.goto("/staff");
    await course.getByLabel("TA username or email for CMSC131").fill(ta.email);
    await course.getByRole("button", { name: "Add TA" }).click();
    await expect(course.locator(`.staff-row[data-userid="${ta.userid}"]`)).toContainText("TA");

    // 5. The TA sees the course, can delete a file in it, but can't add staff or touch other courses.
    const t = await browser.newPage();
    await signIn(t, ta.userid, pw);
    await expect(t.getByRole("link", { name: "Course Staff" })).toBeVisible();
    await t.goto("/staff");
    const taCourse = t.locator('section.course[data-course="CMSC131"]');
    await expect(taCourse.locator(".role-pill")).toHaveText("TA");
    await expect(taCourse.getByRole("button", { name: "Add TA" })).toHaveCount(0);
    t.on("dialog", (d) => d.accept());
    await taCourse.locator(".file-row", { hasText: "leaked-exam.txt" }).getByRole("button", { name: "Delete" }).click();
    await expect(taCourse.locator(".file-row", { hasText: "leaked-exam.txt" })).toHaveCount(0);
    expect(await withDb((db) => db.collection("files").countDocuments({ fileHash: inCourse.fileHash }))).toBe(0);

    const otherId = (await withDb((db) => db.collection("files").findOne({ fileHash: otherCourse.fileHash })))._id.toString();
    expect((await t.request.post("/api/staff/CMSC131/files/delete", { data: { fileId: otherId } })).status()).toBe(404);
    expect((await t.request.post("/api/staff/CMSC132/files/delete", { data: { fileId: otherId } })).status()).toBe(403);
    expect((await t.request.post("/api/staff/CMSC131/tas", { data: { ta: student.userid } })).status()).toBe(403);
    expect((await stu.request.post("/api/staff/CMSC131/files/delete", { data: { fileId: otherId } })).status()).toBe(403);
    expect(await withDb((db) => db.collection("files").countDocuments({ fileHash: otherCourse.fileHash }))).toBe(1);

    // 6. Students see who uploaded official material.
    await stu.goto("/dashboard");
    await expect(stu.locator('.file-card[data-name="official-slides.txt"] .staff-badge')).toHaveText(/From the professor/);

    // 7. The professor removes the TA; the TA loses access.
    pr.on("dialog", (d) => d.accept());
    await pr.goto("/staff");
    await course.locator(`.staff-row[data-userid="${ta.userid}"]`).getByRole("button", { name: "Remove TA" }).click();
    await expect(course.locator(`.staff-row[data-userid="${ta.userid}"]`)).toHaveCount(0);
    await t.goto("/staff");
    await expect(t.getByText("You're not staff for any course yet.")).toBeVisible();
});
