// The verify flow (.claude/skills/verify/SKILL.md): a student signs in, finds a classmate's note
// on the dashboard by searching, and the page holds up at phone and desktop width. Screenshots go
// to test-results/verify/ as evidence for the PR. Writes to the test database, so never @live.
const { expect, test } = require("@playwright/test");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb, "needs a local MongoDB: run `npm run verify`, which starts one");

const user = { userid: "verify_student", firstname: "Vera", lastname: "Fy", email: "verify_student@terpmail.umd.edu" };
const shots = "test-results/verify";

function note(name, classCode, category) {
    return {
        filename: `${Date.now()}_${Math.random().toString(36).slice(2)}_${name}`,
        originalName: name,
        classCode,
        major: classCode.replace(/\d.*/, ""),
        professor: "Test Professor",
        semester: "Fall",
        year: "2026",
        category,
        description: `${name} for ${classCode}`,
        uploadedBy: "verify_classmate",
        uploadDate: new Date(),
        size: 2048,
        downloadCount: 0,
        mimetype: "text/plain",
        fileHash: `verify-${name}`,
        school: "umd",
        virusScanStatus: "clean",
    };
}

test.beforeEach(async () => {
    await withDb(async (db) => {
        await db.collection("files").deleteMany({ uploadedBy: "verify_classmate" });
        await db.collection("files").insertMany([
            note("dijkstra-review.txt", "CMSC351", "Study Guide"),
            note("regex-lecture.txt", "CMSC330", "Lecture Notes"),
        ]);
    });
});

test("a student signs in and finds a note by searching, at desktop and phone width", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await signIn(page, user.userid, await seedUser(user));
    await expect(page.locator(".tn-side-user-name")).toContainText(user.firstname);
    await expect(page.locator('.tn-file[data-name="dijkstra-review.txt"]')).toBeVisible();

    await page.getByLabel("Search notes").fill("dijkstra");
    await expect(page.locator(".tn-file")).toHaveCount(1);
    await expect(page.locator('.tn-file[data-name="dijkstra-review.txt"]')).toBeVisible();
    await page.screenshot({ path: `${shots}/dashboard-desktop.png`, fullPage: true });

    await page.setViewportSize({ width: 390, height: 844 });
    await page.reload();
    await expect(page.locator('.tn-file[data-name="dijkstra-review.txt"]')).toBeVisible();
    const sideways = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(sideways).toBeLessThanOrEqual(0);
    await page.screenshot({ path: `${shots}/dashboard-phone.png`, fullPage: true });
});
