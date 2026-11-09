// Shared test helpers. Tests that use these need a local MongoDB (CI provides one).
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");

const mongoUrl = process.env.MONGO_CONNECTION_STRING;
const DB = "terpnotes_e2e";

async function withDb(fn) {
    const client = new MongoClient(mongoUrl);
    await client.connect();
    try {
        return await fn(client.db(DB));
    } finally {
        await client.close();
    }
}

/** Creates (or recreates) a verified user and returns their password. */
async function seedUser(user, password = "correct horse battery staple") {
    await withDb(async (db) => {
        const users = db.collection("users");
        await users.deleteMany({ userid: user.userid });
        await users.insertOne({
            role: "contributor",
            isVerified: true,
            createdAt: new Date(),
            ...user,
            pass: await bcrypt.hash(password, 10),
        });
    });
    return password;
}

async function signIn(page, userid, password) {
    await page.goto("/login");
    await page.getByLabel("Username").fill(userid);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: "Login" }).click();
    await page.waitForURL(/\/dashboard$/);
}

const needsDb = !mongoUrl || Boolean(process.env.BASE_URL);

module.exports = { withDb, seedUser, signIn, needsDb, DB };
