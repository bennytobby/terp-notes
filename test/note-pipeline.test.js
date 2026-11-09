const assert = require("node:assert/strict");
const { test } = require("node:test");
const { mimeForName, withExtension, assessNote } = require("../utils/note-pipeline");

test("types come from extensions; unknown imports are Markdown", () => {
    assert.equal(mimeForName("Lecture.PDF"), "application/pdf");
    assert.equal(mimeForName("notes.docx"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    assert.equal(mimeForName("Week 1. Intro"), "text/markdown");
    assert.equal(mimeForName("readme.txt"), "text/plain");
});

test("Drive files get the right extension even when the name has a dot", () => {
    const docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    assert.equal(withExtension("Week 1. Intro", docx), "Week 1. Intro.docx");
    assert.equal(withExtension("Lecture 3", "application/pdf"), "Lecture 3.pdf");
    assert.equal(withExtension("slides.pdf", "application/pdf"), "slides.pdf");
    assert.equal(withExtension("odd", "application/x-unknown"), "odd");
});

test("imports are scanned like uploads; a roster is held", async () => {
    const roster = "Name, UID\nA, 117000001\nB, 117000002\nC, 117000003";
    const r = await assessNote({ buffer: Buffer.from(roster), mimetype: "text/markdown", name: "roster.md" });
    assert.equal(r.quarantined, true);
    assert.equal(r.confidentialScan.level, "high");
    assert.match(r.text, /117000001/, "text is returned for indexing");
    assert.ok(!("text" in r.confidentialScan), "text never lands in the stored scan result");

    const clean = await assessNote({ buffer: Buffer.from("Recursion basics"), mimetype: "text/plain", name: "r.txt" });
    assert.equal(clean.quarantined, false);
    assert.equal(clean.confidentialScan.status, "clean");
});

test("duplicates reuse the earlier result, and an approved file stays visible", async () => {
    const existingFile = { confidentialScan: { status: "flagged", level: "high", findings: [], reviewed: true } };
    const r = await assessNote({ buffer: Buffer.from("x"), mimetype: "text/plain", name: "x.txt", existingFile, scan: () => { throw new Error("should not scan"); } });
    assert.equal(r.quarantined, false);
    assert.equal(r.text, null);
});

test("a scanner failure never blocks the note", async () => {
    const r = await assessNote({ buffer: Buffer.from("x"), mimetype: "text/plain", name: "x.txt", scan: async () => { throw new Error("boom"); } });
    assert.equal(r.confidentialScan.status, "error");
    assert.equal(r.quarantined, false);
});
