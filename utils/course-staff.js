/**
 * Course staff: professors and TAs, scoped to one course each.
 *
 * - Site admins invite a professor to a course by email. The invite is a one-time link
 *   (only its SHA-256 hash is stored) that expires after 14 days and must be accepted by a
 *   signed-in account whose email matches the invite.
 * - A professor can add and remove TAs for their own courses.
 * - Professors and TAs can moderate their course: delete its files and review its flagged files.
 *
 * Collections: courseStaff { classCode, userid, role, addedBy, addedAt }
 *              staffInvites { tokenHash, email, classCode, role, invitedBy, createdAt,
 *                             expiresAt, acceptedBy, acceptedAt }
 */
const crypto = require("crypto");

const INVITE_DAYS = 14;
const ROLES = ["professor", "ta"];

/** "cmsc 131" -> "CMSC131". Returns null when it doesn't look like a course code. */
function normalizeCourse(code) {
    const c = String(code || "").toUpperCase().replace(/\s+/g, "");
    return /^[A-Z]{2,5}\d{2,4}[A-Z]{0,2}$/.test(c) ? c : null;
}

/** Lower-cases, and treats @umd.edu and @terpmail.umd.edu as the same mailbox (as signup does). */
function canonicalEmail(email) {
    const e = String(email || "").trim().toLowerCase();
    const at = e.lastIndexOf("@");
    if (at < 1) return null;
    const local = e.slice(0, at);
    let domain = e.slice(at + 1);
    if (domain === "umd.edu") domain = "terpmail.umd.edu";
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return null;
    return `${local}@${domain}`;
}

function emailsMatch(a, b) {
    const ca = canonicalEmail(a);
    return Boolean(ca) && ca === canonicalEmail(b);
}

function hashToken(token) {
    return crypto.createHash("sha256").update(String(token)).digest("hex");
}

function newToken() {
    return crypto.randomBytes(32).toString("hex");
}

let usersCollection = "users";
/** The app's user collection name comes from MONGO_USERCOLLECTION. */
function setUsersCollection(name) {
    if (name) usersCollection = name;
}

function collections(db) {
    return { staff: db.collection("courseStaff"), invites: db.collection("staffInvites"), users: db.collection(usersCollection) };
}

async function ensureIndexes(db) {
    const { staff, invites } = collections(db);
    await staff.createIndex({ classCode: 1, userid: 1 }, { unique: true });
    await staff.createIndex({ userid: 1 });
    await invites.createIndex({ tokenHash: 1 }, { unique: true });
}

/** Creates a professor invite. Returns { token, invite } - the raw token is never stored. */
async function createInvite(db, { email, classCode, invitedBy, role = "professor" }) {
    const course = normalizeCourse(classCode);
    const canonical = canonicalEmail(email);
    if (!course) throw new StaffError("That doesn't look like a course code (for example CMSC131).");
    if (!canonical) throw new StaffError("Enter a valid email address.");
    if (!ROLES.includes(role)) throw new StaffError("Unknown role.");
    const token = newToken();
    const now = new Date();
    const invite = {
        tokenHash: hashToken(token),
        email: canonical,
        classCode: course,
        role,
        invitedBy,
        createdAt: now,
        expiresAt: new Date(now.getTime() + INVITE_DAYS * 24 * 60 * 60 * 1000),
        acceptedBy: null,
        acceptedAt: null,
    };
    await collections(db).invites.insertOne(invite);
    return { token, invite };
}

/** Looks up a still-usable invite by raw token, or explains why it can't be used. */
async function findInvite(db, token) {
    if (!/^[a-f0-9]{64}$/.test(String(token || ""))) return { error: "This invite link isn't valid." };
    const invite = await collections(db).invites.findOne({ tokenHash: hashToken(token) });
    if (!invite) return { error: "This invite link isn't valid." };
    if (invite.acceptedAt) return { error: "This invite has already been used." };
    if (invite.expiresAt < new Date()) return { error: "This invite has expired. Ask an admin for a new one." };
    return { invite };
}

/** Accepts an invite for a signed-in user whose email matches it. */
async function acceptInvite(db, token, user) {
    const { invite, error } = await findInvite(db, token);
    if (error) throw new StaffError(error);
    if (!emailsMatch(invite.email, user.email)) {
        throw new StaffError(`This invite is for ${invite.email}. Sign in with that account to accept it.`);
    }
    const { invites, staff } = collections(db);
    // Claim the invite atomically so it can only be used once.
    const claimed = await invites.updateOne(
        { _id: invite._id, acceptedAt: null },
        { $set: { acceptedBy: user.userid, acceptedAt: new Date() } },
    );
    if (claimed.modifiedCount !== 1) throw new StaffError("This invite has already been used.");
    await staff.updateOne(
        { classCode: invite.classCode, userid: user.userid },
        {
            $set: { role: invite.role, addedBy: invite.invitedBy },
            $setOnInsert: { classCode: invite.classCode, userid: user.userid, addedAt: new Date() },
        },
        { upsert: true },
    );
    return { classCode: invite.classCode, role: invite.role };
}

async function staffRole(db, userid, classCode) {
    const course = normalizeCourse(classCode);
    if (!userid || !course) return null;
    const row = await collections(db).staff.findOne({ classCode: course, userid });
    return row ? row.role : null;
}

async function coursesFor(db, userid) {
    if (!userid) return [];
    return collections(db).staff.find({ userid }).sort({ classCode: 1 }).toArray();
}

async function staffForCourse(db, classCode) {
    return collections(db).staff.find({ classCode: normalizeCourse(classCode) }).sort({ role: 1, userid: 1 }).toArray();
}

/** Map of "CLASSCODE|userid" -> role, for badges on the dashboard. */
async function staffBadgeMap(db) {
    const rows = await collections(db).staff.find({}, { projection: { classCode: 1, userid: 1, role: 1 } }).toArray();
    return Object.fromEntries(rows.map((r) => [`${r.classCode}|${r.userid}`, r.role]));
}

/** A professor adds a TA (an existing account, by username or email) to their course. */
async function addTa(db, { classCode, professor, ta }) {
    const course = normalizeCourse(classCode);
    if ((await staffRole(db, professor.userid, course)) !== "professor") {
        throw new StaffError("Only this course's professor can add TAs.", 403);
    }
    const { users, staff } = collections(db);
    const key = String(ta || "").trim();
    if (!key) throw new StaffError("Enter the TA's username or email.");
    const canonical = canonicalEmail(key);
    const taUser = await users.findOne(
        canonical ? { email: { $in: [canonical, canonical.replace("@terpmail.umd.edu", "@umd.edu")] } } : { userid: key },
    );
    if (!taUser) throw new StaffError("No Terp Notes account matches that username or email. They need to sign up first.");
    if (taUser.userid === professor.userid) throw new StaffError("You're already the professor for this course.");
    const existing = await staffRole(db, taUser.userid, course);
    if (existing === "professor") throw new StaffError("That person is already a professor for this course.");
    await staff.updateOne(
        { classCode: course, userid: taUser.userid },
        {
            $set: { role: "ta", addedBy: professor.userid },
            $setOnInsert: { classCode: course, userid: taUser.userid, addedAt: new Date() },
        },
        { upsert: true },
    );
    return { userid: taUser.userid, firstname: taUser.firstname, email: taUser.email };
}

/** A professor removes a TA; a site admin can remove anyone. */
async function removeStaff(db, { classCode, actor, userid, actorIsAdmin = false }) {
    const course = normalizeCourse(classCode);
    const target = await staffRole(db, userid, course);
    if (!target) throw new StaffError("That person isn't staff for this course.", 404);
    if (!actorIsAdmin) {
        if ((await staffRole(db, actor.userid, course)) !== "professor") {
            throw new StaffError("Only this course's professor can remove TAs.", 403);
        }
        if (target !== "ta") throw new StaffError("Professors can only remove TAs. Ask an admin to change professors.", 403);
    }
    await collections(db).staff.deleteOne({ classCode: course, userid });
}

class StaffError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

module.exports = {
    INVITE_DAYS,
    setUsersCollection,
    normalizeCourse,
    canonicalEmail,
    emailsMatch,
    hashToken,
    ensureIndexes,
    createInvite,
    findInvite,
    acceptInvite,
    staffRole,
    coursesFor,
    staffForCourse,
    staffBadgeMap,
    addTa,
    removeStaff,
    StaffError,
};
