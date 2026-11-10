/**
 * The details every note carries (course, professor, term, category, description), checked the
 * same way whether the note was uploaded or imported from Google Drive, Notion or OneNote.
 *
 * Also answers course look-ups for the import form from the bundled UMD course cache
 * (data/course-cache.json), so suggestions don't need a live UMD.io call.
 */
const fs = require("fs");
const path = require("path");

const SEMESTERS = ["Fall", "Spring", "Summer", "Winter", "Unknown"];
const CATEGORIES = [
    "Exam",
    "Lecture Notes",
    "Homework",
    "Study Guide",
    "Cheat Sheet",
    "Project",
    "Lab",
    "Textbook",
    "Practice Problems",
    "Other",
];
const COURSE_CODE = /^[A-Z]{2,5}\d{3}[A-Z]?$/;

/**
 * Cleans and checks note details. Returns { details, errors }; `errors` maps a field to a message.
 * `fallbackDescription` fills an empty description (imports use the document's name).
 */
function normalizeNoteDetails(input = {}, { fallbackDescription = "", now = new Date() } = {}) {
    const text = (v, max) => String(v ?? "").replace(/\s+/g, " ").trim().slice(0, max);
    const details = {
        classCode: text(input.classCode, 12).toUpperCase().replace(/\s+/g, ""),
        professor: text(input.professor, 80),
        semester: text(input.semester, 10),
        year: text(input.year, 4),
        category: text(input.category, 30),
        description: text(input.description, 300) || text(fallbackDescription, 300),
    };
    const errors = {};
    if (!details.classCode) errors.classCode = "Enter the class code, e.g. CMSC330.";
    else if (!COURSE_CODE.test(details.classCode)) errors.classCode = "Use a class code like CMSC330 or HIST289I.";
    if (!details.professor) errors.professor = "Enter the professor's name.";
    if (!SEMESTERS.includes(details.semester)) errors.semester = "Pick a semester.";
    const year = Number(details.year);
    const thisYear = now.getFullYear();
    if (!/^\d{4}$/.test(details.year) || year < thisYear - 15 || year > thisYear + 1) errors.year = "Pick a year.";
    if (!CATEGORIES.includes(details.category)) errors.category = "Pick a category.";
    if (!details.description) errors.description = "Add a short description, e.g. Week 3 lecture notes.";
    // The department prefix: CMSC330 -> CMSC, HIST289I -> HIST.
    details.major = (details.classCode.match(/^[A-Z]+/) || [details.classCode])[0];
    return { details, errors };
}

// ---------- course look-ups ----------

let courseCache = null;
function loadCourses(file = path.join(__dirname, "..", "data", "course-cache.json")) {
    if (courseCache) return courseCache;
    try {
        courseCache = JSON.parse(fs.readFileSync(file, "utf8")).courses || {};
    } catch (err) {
        console.error("Course cache unavailable:", err.message);
        courseCache = {};
    }
    return courseCache;
}

/** Up to `limit` courses whose code or name matches `query`; codes that start with it come first. */
function suggestCourses(query, { courses = loadCourses(), limit = 8 } = {}) {
    const q = String(query || "").trim().toUpperCase().replace(/\s+/g, "");
    const words = String(query || "").trim().toLowerCase();
    if (q.length < 2) return [];
    const scored = [];
    for (const [id, entry] of Object.entries(courses)) {
        const name = String(entry?.courseInfo?.name || "").replace(/^Course /, "");
        let rank = -1;
        if (id.startsWith(q)) rank = 0;
        else if (id.includes(q)) rank = 1;
        else if (words.length >= 3 && name.toLowerCase().includes(words)) rank = 2;
        if (rank >= 0) scored.push({ id, name, rank });
    }
    return scored
        .sort((a, b) => a.rank - b.rank || a.id.localeCompare(b.id))
        .slice(0, limit)
        .map(({ id, name }) => ({ id, name }));
}

const TERM_ORDER = { Winter: 0, Spring: 1, Summer: 2, Fall: 3, Unknown: -1 };

/** A course's name and who taught it, most recent teachers first. Null for unknown courses. */
function courseDetails(code, { courses = loadCourses() } = {}) {
    const id = String(code || "").trim().toUpperCase().replace(/\s+/g, "");
    const entry = courses[id];
    if (!entry) return null;
    const professors = Object.entries(entry.professors || {})
        .map(([name, terms]) => {
            const sorted = [...(terms || [])].sort(
                (a, b) => b.year - a.year || (TERM_ORDER[b.semester] ?? -1) - (TERM_ORDER[a.semester] ?? -1),
            );
            return { name, terms: sorted.slice(0, 4).map((t) => ({ semester: t.semester, year: t.year })) };
        })
        .filter((p) => p.name && p.name.trim() && p.name !== "Instructor: TBA")
        .sort((a, b) => {
            const ta = a.terms[0] || { year: 0 };
            const tb = b.terms[0] || { year: 0 };
            return tb.year - ta.year || (TERM_ORDER[tb.semester] ?? -1) - (TERM_ORDER[ta.semester] ?? -1) || a.name.localeCompare(b.name);
        });
    return { id, name: String(entry.courseInfo?.name || "").replace(/^Course /, ""), professors };
}

/** The term a student is most likely to be in right now. */
function currentTerm(now = new Date()) {
    const m = now.getMonth();
    const semester = m <= 0 ? "Winter" : m <= 4 ? "Spring" : m <= 7 ? "Summer" : "Fall";
    return { semester, year: String(now.getFullYear()) };
}

module.exports = { normalizeNoteDetails, suggestCourses, courseDetails, currentTerm, SEMESTERS, CATEGORIES, COURSE_CODE };
