/**
 * Schools Terp Notes serves. A user's school comes from their email domain (no migration
 * needed); every file is tagged with its uploader's school, and students only see their own
 * school's notes. Files from before multi-school support have no tag and count as UMD.
 *
 * To add a school: append an entry here, then deploy. That's all.
 */
const SCHOOLS = [
    {
        id: "umd",
        name: "University of Maryland",
        short: "UMD",
        domains: ["umd.edu", "terpmail.umd.edu"],
        // @umd.edu and @terpmail.umd.edu are the same mailbox; store one form.
        storageDomain: "terpmail.umd.edu",
        courseCatalog: true, // course and professor autocomplete from UMD.io
    },
    {
        id: "umbc",
        name: "University of Maryland, Baltimore County",
        short: "UMBC",
        domains: ["umbc.edu"],
        storageDomain: "umbc.edu",
        courseCatalog: false,
    },
];

const DEFAULT_SCHOOL = "umd";
const byId = Object.fromEntries(SCHOOLS.map((s) => [s.id, s]));

function getSchool(id) {
    return byId[id] || byId[DEFAULT_SCHOOL];
}

function splitEmail(email) {
    const e = String(email || "").trim().toLowerCase();
    const at = e.lastIndexOf("@");
    if (at < 1 || at === e.length - 1) return null;
    return { local: e.slice(0, at), domain: e.slice(at + 1) };
}

/** The school for an email address, or null if no school we serve uses that domain. */
function schoolForEmail(email) {
    const parts = splitEmail(email);
    if (!parts) return null;
    return SCHOOLS.find((s) => s.domains.includes(parts.domain)) || null;
}

/** The address we store (e.g. x@umd.edu -> x@terpmail.umd.edu), or null for other domains. */
function normalizeEmail(email) {
    const parts = splitEmail(email);
    const school = schoolForEmail(email);
    if (!parts || !school) return null;
    return `${parts.local}@${school.storageDomain}`;
}

/** Every form of the address that means the same mailbox, for duplicate checks. */
function equivalentEmails(email) {
    const parts = splitEmail(email);
    const school = schoolForEmail(email);
    if (!parts || !school) return [];
    return school.domains.map((d) => `${parts.local}@${d}`);
}

/** A signed-in user's school id. Users from before multi-school support are UMD. */
function schoolOf(user) {
    if (user && user.school && byId[user.school]) return user.school;
    const s = user && schoolForEmail(user.email);
    return s ? s.id : DEFAULT_SCHOOL;
}

/** Mongo filter for documents of one school; untagged legacy documents belong to UMD. */
function schoolFilter(id) {
    return id === DEFAULT_SCHOOL ? { school: { $in: [DEFAULT_SCHOOL, null] } } : { school: id };
}

function docSchool(doc) {
    return (doc && doc.school) || DEFAULT_SCHOOL;
}

/** "UMD or UMBC" and "@umd.edu, @terpmail.umd.edu or @umbc.edu", for copy. */
function namesList() {
    const shorts = SCHOOLS.map((s) => s.short);
    return shorts.length > 1 ? `${shorts.slice(0, -1).join(", ")} or ${shorts.at(-1)}` : shorts[0];
}

function domainsList() {
    const all = SCHOOLS.flatMap((s) => s.domains).map((d) => `@${d}`);
    return all.length > 1 ? `${all.slice(0, -1).join(", ")} or ${all.at(-1)}` : all[0];
}

module.exports = {
    SCHOOLS,
    DEFAULT_SCHOOL,
    getSchool,
    schoolForEmail,
    normalizeEmail,
    equivalentEmails,
    schoolOf,
    schoolFilter,
    docSchool,
    namesList,
    domainsList,
};
