const assert = require("node:assert/strict");
const { test } = require("node:test");
const s = require("../utils/schools");

test("schools come from email domains", () => {
    assert.equal(s.schoolForEmail("Testudo@UMD.edu").id, "umd");
    assert.equal(s.schoolForEmail("t@terpmail.umd.edu").id, "umd");
    assert.equal(s.schoolForEmail("r@umbc.edu"), null, "UMBC isn't open for sign-up");
    assert.equal(s.schoolForEmail("r@umbc.edu", { includeDisabled: true }).id, "umbc", "but it's still known");
    assert.equal(s.schoolForEmail("x@gmail.com"), null);
    assert.equal(s.schoolForEmail("x@evilumd.edu"), null, "exact domains only");
    assert.equal(s.schoolForEmail("x@umd.edu.attacker.com"), null);
    assert.equal(s.schoolForEmail("not an email"), null);
});

test("emails are stored in one form per mailbox", () => {
    assert.equal(s.normalizeEmail("Testudo@umd.edu"), "testudo@terpmail.umd.edu");
    assert.equal(s.normalizeEmail("r@UMBC.edu"), null, "closed schools can't register");
    assert.equal(s.normalizeEmail("x@gmail.com"), null);
    assert.deepEqual(s.equivalentEmails("t@terpmail.umd.edu"), ["t@umd.edu", "t@terpmail.umd.edu"]);
});

test("a user's school, and filters that keep legacy files at UMD", () => {
    assert.equal(s.schoolOf({ email: "r@umbc.edu" }), "umbc");
    assert.equal(s.schoolOf({ email: "t@terpmail.umd.edu" }), "umd");
    assert.equal(s.schoolOf({ email: "old@unknown.org" }), "umd", "legacy users default to UMD");
    assert.equal(s.schoolOf({ school: "umbc", email: "x@umd.edu" }), "umbc", "a stored school wins");
    assert.deepEqual(s.schoolFilter("umd"), { school: { $in: ["umd", null] } });
    assert.deepEqual(s.schoolFilter("umbc"), { school: "umbc" });
    assert.equal(s.docSchool({}), "umd");
    assert.equal(s.namesList(), "UMD");
    assert.equal(s.domainsList(), "@umd.edu or @terpmail.umd.edu");
});

test("only UMD is open; every other school stays closed until it gets its own site", () => {
    assert.deepEqual(s.SCHOOLS.filter((x) => x.enabled).map((x) => x.id), ["umd"]);
});
