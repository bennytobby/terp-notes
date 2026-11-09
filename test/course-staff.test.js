const assert = require("node:assert/strict");
const { test } = require("node:test");
const staff = require("../utils/course-staff");
const { fakeDb } = require("./fake-db");

test("course codes and emails are normalized like signup does", () => {
    assert.equal(staff.normalizeCourse("cmsc 131"), "CMSC131");
    assert.equal(staff.normalizeCourse("BMGT110H"), "BMGT110H");
    assert.equal(staff.normalizeCourse("hello"), null);
    assert.equal(staff.normalizeCourse("CMSC131; drop"), null);
    assert.equal(staff.canonicalEmail(" Prof@UMD.edu "), "prof@terpmail.umd.edu");
    assert.ok(staff.emailsMatch("prof@umd.edu", "prof@terpmail.umd.edu"));
    assert.ok(!staff.emailsMatch("prof@umd.edu", "other@umd.edu"));
    assert.equal(staff.canonicalEmail("not-an-email"), null);
});

async function setup() {
    const db = fakeDb();
    await db.collection("users").insertOne({ userid: "prof1", email: "prof1@terpmail.umd.edu", firstname: "Pat" });
    await db.collection("users").insertOne({ userid: "ta1", email: "ta1@terpmail.umd.edu", firstname: "Tia" });
    await db.collection("users").insertOne({ userid: "student1", email: "student1@terpmail.umd.edu", firstname: "Sam" });
    return db;
}

test("an invite is stored hashed and accepted once by the matching account", async () => {
    const db = await setup();
    const { token, invite } = await staff.createInvite(db, { email: "prof1@umd.edu", classCode: "cmsc131", invitedBy: "admin" });
    assert.match(token, /^[a-f0-9]{64}$/);
    assert.equal(invite.classCode, "CMSC131");
    assert.ok(!JSON.stringify(db.collection("staffInvites").docs).includes(token), "raw token must not be stored");

    await assert.rejects(
        staff.acceptInvite(db, token, { userid: "student1", email: "student1@terpmail.umd.edu" }),
        /Sign in with that account/,
    );
    const accepted = await staff.acceptInvite(db, token, { userid: "prof1", email: "prof1@terpmail.umd.edu" });
    assert.deepEqual(accepted, { classCode: "CMSC131", role: "professor" });
    assert.equal(await staff.staffRole(db, "prof1", "cmsc131"), "professor");
    await assert.rejects(staff.acceptInvite(db, token, { userid: "prof1", email: "prof1@terpmail.umd.edu" }), /already been used/);
});

test("expired and malformed invites are refused", async () => {
    const db = await setup();
    const { token } = await staff.createInvite(db, { email: "prof1@umd.edu", classCode: "CMSC131", invitedBy: "admin" });
    db.collection("staffInvites").docs[0].expiresAt = new Date(Date.now() - 1000);
    assert.match((await staff.findInvite(db, token)).error, /expired/);
    assert.match((await staff.findInvite(db, "../../etc")).error, /isn't valid/);
});

test("only the professor adds and removes TAs, and only TAs", async () => {
    const db = await setup();
    const { token } = await staff.createInvite(db, { email: "prof1@umd.edu", classCode: "CMSC131", invitedBy: "admin" });
    await staff.acceptInvite(db, token, { userid: "prof1", email: "prof1@terpmail.umd.edu" });
    const prof = { userid: "prof1" };

    await assert.rejects(staff.addTa(db, { classCode: "CMSC131", professor: { userid: "student1" }, ta: "ta1" }), /Only this course's professor/);
    await assert.rejects(staff.addTa(db, { classCode: "CMSC131", professor: prof, ta: "nobody" }), /need to sign up/);
    const added = await staff.addTa(db, { classCode: "CMSC131", professor: prof, ta: "ta1@umd.edu" });
    assert.equal(added.userid, "ta1");
    assert.equal(await staff.staffRole(db, "ta1", "CMSC131"), "ta");
    assert.equal(await staff.staffRole(db, "ta1", "CMSC132"), null, "staff roles are per course");

    // A TA can't add or remove anyone; a professor can't remove another professor.
    await assert.rejects(staff.addTa(db, { classCode: "CMSC131", professor: { userid: "ta1" }, ta: "student1" }), /Only this course's professor/);
    await assert.rejects(staff.removeStaff(db, { classCode: "CMSC131", actor: { userid: "ta1" }, userid: "prof1" }), /Only this course's professor/);
    await assert.rejects(staff.removeStaff(db, { classCode: "CMSC131", actor: prof, userid: "prof1" }), /only remove TAs/);

    await staff.removeStaff(db, { classCode: "CMSC131", actor: prof, userid: "ta1" });
    assert.equal(await staff.staffRole(db, "ta1", "CMSC131"), null);
    const badges = await staff.staffBadgeMap(db);
    assert.deepEqual(badges, { "CMSC131|prof1": "professor" });
});
