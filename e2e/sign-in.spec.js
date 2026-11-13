// The core flow: a verified student signs in and reaches the dashboard.
// Needs MongoDB (CI runs it as a service). Writes data, so it is never run against production.
const { expect, test } = require("@playwright/test");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");

const mongoUrl = process.env.MONGO_CONNECTION_STRING;
test.skip(!mongoUrl || Boolean(process.env.BASE_URL), "needs a local MongoDB (set MONGO_CONNECTION_STRING)");

const user = {
    userid: "e2e_student",
    firstname: "Testudo",
    lastname: "Terrapin",
    email: "e2e_student@terpmail.umd.edu",
    role: "contributor",
    isVerified: true,
};
const password = "correct horse battery staple";

test.beforeAll(async () => {
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const users = client.db("terpnotes_e2e").collection("users");
    await users.deleteMany({ userid: user.userid });
    await users.insertOne({ ...user, pass: await bcrypt.hash(password, 10), createdAt: new Date() });
    await client.close();
});

test("a verified student signs in, sees the dashboard, and gets a real 404", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill(user.userid);
    await page.getByLabel("Password").fill("wrong password");
    await page.getByRole("button", { name: "Log in", exact: true }).click();
    await expect(page).not.toHaveURL(/\/dashboard/);

    await page.goto("/login");
    await page.getByLabel("Username").fill(user.userid);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: "Log in", exact: true }).click();
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator(".tn-side-user-name")).toContainText(user.firstname);

    await page.goto("/this-page-does-not-exist");
    await expect(page.getByRole("heading", { name: "Page Not Found" })).toBeVisible();
});
