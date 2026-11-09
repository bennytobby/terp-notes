/**
 * MCP server: lets a student use their Terp Notes course notes from ChatGPT, Claude and other
 * AI apps. Read-only tools; every call acts as the token's owner, and files held for review
 * are never returned.
 *
 * Auth is a personal access token (created on /ai-access, stored as a SHA-256 hash), sent as
 *   - `Authorization: Bearer tn_...` (Claude Code, Claude Desktop, most MCP clients), or
 *   - part of a private URL, /mcp/tn_..., for apps whose connector form only offers
 *     "No authentication" (ChatGPT, Claude.ai). Treat that URL like a password.
 */
const crypto = require("crypto");
const { z } = require("zod");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const studyBuddy = require("./study-buddy");
const schools = require("./schools");

const TOKEN_RE = /^tn_[a-f0-9]{40}$/;
const MAX_TOKENS_PER_USER = 10;
const MAX_NOTE_CHARS = 20000;

const hashToken = (t) => crypto.createHash("sha256").update(String(t)).digest("hex");

class TokenError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

async function createToken(db, userid, name) {
    const tokens = db.collection("apiTokens");
    const label = String(name || "").trim().slice(0, 60) || "AI app";
    const active = await tokens.countDocuments({ userid, revokedAt: null });
    if (active >= MAX_TOKENS_PER_USER) throw new TokenError(`You can have up to ${MAX_TOKENS_PER_USER} active tokens. Revoke one first.`);
    const token = `tn_${crypto.randomBytes(20).toString("hex")}`;
    const doc = {
        id: crypto.randomBytes(8).toString("hex"),
        tokenHash: hashToken(token),
        prefix: token.slice(0, 7),
        userid,
        name: label,
        createdAt: new Date(),
        lastUsedAt: null,
        revokedAt: null,
    };
    await tokens.insertOne(doc);
    return { token, id: doc.id, name: label };
}

async function listTokens(db, userid) {
    const rows = await db.collection("apiTokens").find({ userid, revokedAt: null }).sort({ createdAt: -1 }).toArray();
    return rows.map(({ id, prefix, name, createdAt, lastUsedAt }) => ({ id, prefix, name, createdAt, lastUsedAt }));
}

async function revokeToken(db, userid, id) {
    const r = await db.collection("apiTokens").updateOne({ id: String(id), userid, revokedAt: null }, { $set: { revokedAt: new Date() } });
    if (!r.modifiedCount) throw new TokenError("Token not found.", 404);
}

/** True while a ban is in force (the app stores bans as banStatus; timed bans expire). */
function isBanned(user) {
    const ban = user && user.banStatus;
    if (!ban || !ban.isBanned) return false;
    return !(ban.banType === "timed" && ban.banExpiry && new Date(ban.banExpiry) < new Date());
}

/** Returns the token's user (fresh from the users collection) or null. Banned users are refused. */
async function authenticate(db, usersCollection, token) {
    if (!TOKEN_RE.test(String(token || ""))) return null;
    const tokens = db.collection("apiTokens");
    const row = await tokens.findOne({ tokenHash: hashToken(token), revokedAt: null });
    if (!row) return null;
    const user = await db.collection(usersCollection).findOne({ userid: row.userid });
    if (!user || isBanned(user)) return null;
    await tokens.updateOne({ id: row.id }, { $set: { lastUsedAt: new Date() } });
    return { userid: user.userid, role: user.role, firstname: user.firstname, school: schools.schoolOf(user), tokenId: row.id };
}

/** Pulls a token from the Authorization header or the /mcp/:token path. */
function tokenFromRequest(req) {
    const header = req.get ? req.get("authorization") : req.headers?.authorization;
    const bearer = /^Bearer\s+(\S+)$/i.exec(header || "");
    return bearer ? bearer[1] : req.params?.token || null;
}

const json = (value) => ({ content: [{ type: "text", text: JSON.stringify(value, null, 2) }] });

/** Builds an MCP server whose tools read Terp Notes as `user`. */
function buildServer({ db, filesCollection, baseUrl, user }) {
    const server = new McpServer(
        { name: "terp-notes", version: "1.0.0" },
        { instructions: "Course notes shared by University of Maryland students on Terp Notes. Search a course's notes, read a note, and cite the note title and link when you use it." },
    );
    const fileUrl = (filename) => `${baseUrl}/download/${encodeURIComponent(filename)}`;
    const readOnly = { readOnlyHint: true, openWorldHint: false };

    // Only the user's own school's notes.
    const scope = schools.schoolFilter(user.school || schools.schoolOf(user));

    async function visibleNotes(filter = {}) {
        const notes = await db.collection("noteTexts").find({ ...filter, ...scope }).limit(2000).toArray();
        if (!notes.length) return [];
        const fileIds = new Set(notes.map((n) => n.fileId));
        const files = await db.collection(filesCollection).find(scope).toArray();
        const ok = new Set(
            files
                .filter((f) => fileIds.has(String(f._id)))
                .filter((f) => !f.quarantined || user.role === "admin" || f.uploadedBy === user.userid)
                .map((f) => String(f._id)),
        );
        return notes.filter((n) => ok.has(n.fileId));
    }

    async function searchPassages(query, course, limit) {
        const filter = course ? { classCode: course } : {};
        const notes = await visibleNotes(filter);
        const passages = notes.flatMap((n) =>
            n.chunks.map((text) => ({ text, fileId: n.fileId, title: n.originalName, course: n.classCode, filename: n.filename })),
        );
        return studyBuddy.rankPassages(query, passages, limit);
    }

    server.registerTool(
        "list_courses",
        { title: "List courses", description: "Courses that have searchable notes, with how many notes each has.", annotations: readOnly },
        async () => {
            const notes = await visibleNotes();
            const counts = {};
            for (const n of notes) counts[n.classCode] = (counts[n.classCode] || 0) + 1;
            return json(Object.entries(counts).sort().map(([course, notes_count]) => ({ course, notes_count })));
        },
    );

    server.registerTool(
        "search_notes",
        {
            title: "Search course notes",
            description: "Find the passages in Terp Notes that best match a question, optionally within one course (e.g. CMSC131). Returns note ids for get_note.",
            inputSchema: {
                query: z.string().min(2).max(500).describe("What to look for"),
                course: z.string().max(12).optional().describe("Course code, e.g. CMSC131"),
                limit: z.number().int().min(1).max(10).optional().describe("How many passages (default 5)"),
            },
            annotations: readOnly,
        },
        async ({ query, course, limit }) => {
            const code = course ? String(course).toUpperCase().replace(/\s+/g, "") : null;
            const hits = await searchPassages(query, code, limit || 5);
            return json(
                hits.map((h) => ({ note_id: h.fileId, title: h.title, course: h.course, url: fileUrl(h.filename), passage: h.text.slice(0, 1200) })),
            );
        },
    );

    server.registerTool(
        "get_note",
        {
            title: "Read a note",
            description: "The text of one note by its note_id (from search_notes or search).",
            inputSchema: { note_id: z.string().min(1).max(64) },
            annotations: readOnly,
        },
        async ({ note_id }) => {
            const [note] = await visibleNotes({ fileId: String(note_id) });
            if (!note) return { isError: true, content: [{ type: "text", text: "No note with that id (or it isn't available)." }] };
            return json({
                note_id: note.fileId,
                title: note.originalName,
                course: note.classCode,
                url: fileUrl(note.filename),
                text: note.chunks.join("\n\n").slice(0, MAX_NOTE_CHARS),
            });
        },
    );

    // ChatGPT's connector convention: `search` returns {results:[{id,title,url}]}, `fetch` returns one document.
    server.registerTool(
        "search",
        {
            title: "Search",
            description: "Search all Terp Notes course notes. Returns ids for fetch.",
            inputSchema: { query: z.string().min(1).max(500) },
            annotations: readOnly,
        },
        async ({ query }) => {
            const hits = await searchPassages(query, null, 8);
            const seen = new Set();
            const results = [];
            for (const h of hits) {
                if (seen.has(h.fileId)) continue;
                seen.add(h.fileId);
                results.push({ id: h.fileId, title: `${h.course}: ${h.title}`, url: fileUrl(h.filename) });
            }
            return { content: [{ type: "text", text: JSON.stringify({ results }) }] };
        },
    );

    server.registerTool(
        "fetch",
        {
            title: "Fetch",
            description: "The full text of a note by id (from search).",
            inputSchema: { id: z.string().min(1).max(64) },
            annotations: readOnly,
        },
        async ({ id }) => {
            const [note] = await visibleNotes({ fileId: String(id) });
            if (!note) return { isError: true, content: [{ type: "text", text: "Not found." }] };
            const doc = {
                id: note.fileId,
                title: `${note.classCode}: ${note.originalName}`,
                text: note.chunks.join("\n\n").slice(0, MAX_NOTE_CHARS),
                url: fileUrl(note.filename),
                metadata: { course: note.classCode },
            };
            return { content: [{ type: "text", text: JSON.stringify(doc) }] };
        },
    );

    return server;
}

module.exports = { TOKEN_RE, hashToken, createToken, listTokens, revokeToken, authenticate, tokenFromRequest, buildServer, TokenError };
