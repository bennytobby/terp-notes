const assert = require("node:assert/strict");
const { test } = require("node:test");
const { normalizeNoteDetails, suggestCourses, courseDetails, currentTerm } = require("../utils/note-details");

const now = new Date("2026-11-09T12:00:00Z");
const good = { classCode: " cmsc 330 ", professor: "  Anwar   Mamat ", semester: "Fall", year: "2026", category: "Lecture Notes", description: "Week 3" };

test("imports need the same class details as an upload, cleaned the same way", () => {
    const { details, errors } = normalizeNoteDetails(good, { now });
    assert.deepEqual(errors, {});
    assert.equal(details.classCode, "CMSC330");
    assert.equal(details.major, "CMSC");
    assert.equal(details.professor, "Anwar Mamat");
    assert.equal(normalizeNoteDetails({ ...good, classCode: "HIST289I" }, { now }).details.major, "HIST");
});

test("missing or made-up details are rejected field by field", () => {
    const { errors } = normalizeNoteDetails({ classCode: "intro", semester: "Autumn", year: "1999", category: "Memes" }, { now });
    assert.deepEqual(Object.keys(errors).sort(), ["category", "classCode", "description", "professor", "semester", "year"]);
});

test("an empty description falls back to the document's name", () => {
    const { details, errors } = normalizeNoteDetails({ ...good, description: "" }, { now, fallbackDescription: "Lecture 4 - Parsing" });
    assert.equal(errors.description, undefined);
    assert.equal(details.description, "Lecture 4 - Parsing");
});

const courses = {
    CMSC330: { courseInfo: { name: "Organization of Programming Languages" }, professors: {
        "Old Prof": [{ semester: "Spring", year: 2022 }],
        "New Prof": [{ semester: "Spring", year: 2026 }, { semester: "Fall", year: 2026 }],
        "Instructor: TBA": [{ semester: "Fall", year: 2026 }],
    } },
    CMSC351: { courseInfo: { name: "Algorithms" }, professors: {} },
    MATH330: { courseInfo: { name: "Advanced Calculus" }, professors: {} },
};

test("course suggestions put codes that start with the query first", () => {
    assert.deepEqual(suggestCourses("cmsc3", { courses }).map((c) => c.id), ["CMSC330", "CMSC351"]);
    assert.deepEqual(suggestCourses("330", { courses }).map((c) => c.id), ["CMSC330", "MATH330"]);
    assert.deepEqual(suggestCourses("algor", { courses }).map((c) => c.id), ["CMSC351"]);
    assert.deepEqual(suggestCourses("c", { courses }), []);
});

test("course details list the most recent professors first and drop TBA", () => {
    const d = courseDetails("cmsc330", { courses });
    assert.equal(d.name, "Organization of Programming Languages");
    assert.deepEqual(d.professors.map((p) => p.name), ["New Prof", "Old Prof"]);
    assert.deepEqual(d.professors[0].terms[0], { semester: "Fall", year: 2026 });
    assert.equal(courseDetails("NOPE101", { courses }), null);
});

test("the bundled UMD catalog loads", () => {
    assert.equal(suggestCourses("CMSC330")[0]?.id, "CMSC330");
});

test("the current term follows the calendar", () => {
    assert.deepEqual(currentTerm(new Date("2026-11-09T12:00:00")), { semester: "Fall", year: "2026" });
    assert.deepEqual(currentTerm(new Date("2026-03-01T12:00:00")), { semester: "Spring", year: "2026" });
    assert.deepEqual(currentTerm(new Date("2026-07-01T12:00:00")), { semester: "Summer", year: "2026" });
});
