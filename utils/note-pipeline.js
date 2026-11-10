/**
 * Steps every new note goes through, whether it was uploaded or imported from an app
 * (Google Drive, Notion, OneNote, Obsidian): work out its type, scan it for confidential
 * information, and decide whether it's held for review. Keeping this in one place means
 * imports can't skip a safety step that uploads have.
 */
const { scanUpload } = require("./confidential-scanner");

const TYPES = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
    ".csv": "text/csv",
};

/** MIME type from a file name; imported notes without a known extension are Markdown. */
function mimeForName(name, fallback = "text/markdown") {
    const m = /\.[a-z0-9]+$/i.exec(String(name || ""));
    return (m && TYPES[m[0].toLowerCase()]) || fallback;
}

/** Adds the extension for a MIME type when the name doesn't already end with it. */
function withExtension(name, mimeType) {
    const ext = Object.entries(TYPES).find(([, t]) => t === mimeType)?.[0];
    const base = String(name || "note").trim() || "note";
    if (!ext || base.toLowerCase().endsWith(ext)) return base;
    return `${base}${ext}`;
}

const TIMED_OUT = Symbol("timed out");

/**
 * Scans a note. A duplicate of an existing file reuses its result (same bytes).
 * Returns { confidentialScan, quarantined, text } - `text` is for indexing, never for storage.
 *
 * With `timeoutMs`, a scan that runs long (a big PDF on a serverless request) is left as
 * status "pending" instead of failing the upload; the admin "Index older notes" job finishes it.
 */
async function assessNote({ buffer, mimetype, name, existingFile, scan = scanUpload, timeoutMs = 0 }) {
    let confidentialScan;
    let text = null;
    if (existingFile && existingFile.confidentialScan && existingFile.confidentialScan.status !== "pending") {
        confidentialScan = existingFile.confidentialScan;
    } else {
        try {
            const run = Promise.resolve().then(() => scan(buffer, mimetype, name));
            let timer;
            const result = timeoutMs
                ? await Promise.race([run, new Promise((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), timeoutMs); })])
                : await run;
            clearTimeout(timer);
            if (result === TIMED_OUT) {
                run.catch(() => {});
                confidentialScan = { status: "pending", level: "none", findings: [], reason: "scan took too long during upload" };
            } else {
                const { text: extracted, ...rest } = result;
                confidentialScan = rest;
                text = extracted;
            }
        } catch (err) {
            confidentialScan = { status: "error", level: "none", findings: [] };
        }
        confidentialScan.scannedAt = new Date();
    }
    const quarantined = confidentialScan.level === "high" && !confidentialScan.reviewed;
    return { confidentialScan, quarantined, text };
}

module.exports = { mimeForName, withExtension, assessNote, TYPES };
