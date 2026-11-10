/**
 * Schools. Terp Notes is for UMD students only; the rest of this file keeps the door open for
 * other schools later (most likely each on its own site, since "Terp Notes" is a UMD name).
 *
 * A user's school comes from their email domain; every file is tagged with its uploader's
 * school, and students only see their own school's notes. Files from before multi-school
 * support have no tag and count as UMD.
 *
 * Only `enabled` schools can sign up. A disabled school is still known, so any account or
 * file already tagged with it keeps working and stays separate from UMD's notes.
 * To open a school: set `enabled: true` (and give it its own site if it gets one), then deploy.
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
        enabled: true,
    },
    {
        id: "umbc",
        name: "University of Maryland, Baltimore County",
        short: "UMBC",
        domains: ["umbc.edu"],
        storageDomain: "umbc.edu",
        courseCatalog: false,
        // Not open yet: Param plans other schools as separate sites, not part of terp-notes.org.
        enabled: false,
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

const ENABLED = SCHOOLS.filter((s) => s.enabled);

/**
 * The school for an email address, or null if no school that's open for sign-up uses that
 * domain. `includeDisabled` also matches known schools that aren't open (existing accounts).
 */
function schoolForEmail(email, { includeDisabled = false } = {}) {
    const parts = splitEmail(email);
    if (!parts) return null;
    return (includeDisabled ? SCHOOLS : ENABLED).find((s) => s.domains.includes(parts.domain)) || null;
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
    const s = user && schoolForEmail(user.email, { includeDisabled: true });
    return s ? s.id : DEFAULT_SCHOOL;
}

/** Mongo filter for documents of one school; untagged legacy documents belong to UMD. */
function schoolFilter(id) {
    return id === DEFAULT_SCHOOL ? { school: { $in: [DEFAULT_SCHOOL, null] } } : { school: id };
}

function docSchool(doc) {
    return (doc && doc.school) || DEFAULT_SCHOOL;
}

/** Open schools for copy: "UMD" and "@umd.edu or @terpmail.umd.edu" (more as schools open). */
function namesList() {
    const shorts = ENABLED.map((s) => s.short);
    return shorts.length > 1 ? `${shorts.slice(0, -1).join(", ")} or ${shorts.at(-1)}` : shorts[0];
}

function domainsList() {
    const all = ENABLED.flatMap((s) => s.domains).map((d) => `@${d}`);
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
