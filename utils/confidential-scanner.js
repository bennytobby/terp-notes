/**
 * Confidential-information scanner for uploads.
 *
 * Runs alongside the VirusTotal malware scan. It extracts text from the upload and looks
 * for things that should not be shared on a class-notes site:
 *
 *   high   (file is held for admin review, hidden from other students)
 *          - US Social Security numbers
 *          - payment card numbers (Luhn-valid)
 *          - lists of student IDs (a roster or gradebook)
 *          - private keys and cloud credentials
 *   medium (file stays visible, flagged for an admin to look at)
 *          - exam / answer keys and instructor-only material
 *          - "confidential" / "do not distribute" markings
 *          - many personal emails or phone numbers (a contact list)
 *
 * Rules favour precision over recall: a false "high" hides a student's notes, so every high
 * rule needs a strong signal. Findings carry masked samples only, never the raw value.
 */

const MAX_TEXT = 2_000_000; // characters scanned per file

// ---------- text extraction ----------

const TEXT_TYPES = /^(text\/|application\/(json|xml|csv|x-tex|rtf))/;
const TEXT_EXT = /\.(txt|md|markdown|csv|tsv|json|tex|rtf|html?|xml)$/i;

let unpdf;
/** unpdf: PDF.js built for serverless, with no native modules (pdf-parse needed @napi-rs/canvas,
 * which Vercel's bundle didn't include, so every PDF failed in production). */
async function pdfText(buffer) {
    unpdf ||= import("unpdf");
    const { getDocumentProxy, extractText: pdfExtract } = await unpdf;
    const pdf = await getDocumentProxy(new Uint8Array(buffer));
    try {
        const { text } = await pdfExtract(pdf, { mergePages: true });
        return text || "";
    } finally {
        await Promise.resolve(pdf.destroy?.()).catch(() => {});
    }
}

/**
 * Text from an upload, with why it failed. `reason` is "unsupported" for formats we don't read
 * (images, archives, slides) and "error: <message>" when reading a supported format failed.
 */
async function readText(buffer, mimetype = "", name = "") {
    try {
        if (mimetype === "application/pdf" || /\.pdf$/i.test(name)) {
            return { text: await pdfText(buffer), reason: null };
        }
        if (
            mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
            /\.docx$/i.test(name)
        ) {
            const mammoth = require("mammoth");
            const { value } = await mammoth.extractRawText({ buffer });
            return { text: value || "", reason: null };
        }
        if (TEXT_TYPES.test(mimetype) || TEXT_EXT.test(name)) {
            return { text: buffer.toString("utf8"), reason: null };
        }
        return { text: null, reason: "unsupported" };
    } catch (err) {
        // Corrupt or password-protected files: report as unreadable rather than failing the upload.
        return { text: null, reason: `error: ${String(err && err.message ? err.message : err).slice(0, 200)}` };
    }
}

/**
 * Best-effort text from an upload. Returns null for formats we can't read (images,
 * archives, slides) and for files that fail to parse, which the caller records as "skipped".
 */
async function extractText(buffer, mimetype = "", name = "") {
    return (await readText(buffer, mimetype, name)).text;
}

// ---------- detectors ----------

function mask(value, keep = 4) {
    const s = String(value).replace(/\s+/g, "");
    if (s.length <= keep) return "*".repeat(s.length);
    return `${"*".repeat(Math.min(s.length - keep, 8))}${s.slice(-keep)}`;
}

function luhn(digits) {
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let d = digits.charCodeAt(i) - 48;
        if (double) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        double = !double;
    }
    return sum % 10 === 0;
}

function uniq(arr) {
    return [...new Set(arr)];
}

const detectors = [
    {
        type: "ssn",
        level: "high",
        label: "Social Security number",
        find(text) {
            // Dashed form only: bare 9-digit numbers are too often IDs or page numbers.
            const re = /\b(?!000|666|9\d\d)(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b/g;
            return uniq([...text.matchAll(re)].map((m) => m[0]));
        },
    },
    {
        type: "payment_card",
        level: "high",
        label: "Payment card number",
        find(text) {
            const re = /\b(?:\d[ -]?){13,19}\b/g;
            return uniq(
                [...text.matchAll(re)]
                    .map((m) => m[0].replace(/[ -]/g, ""))
                    .filter((d) => d.length >= 13 && d.length <= 19)
                    .filter((d) => /^(4|5[1-5]|2[2-7]|3[47]|6(011|5))/.test(d))
                    .filter((d) => !/^(\d)\1+$/.test(d))
                    .filter(luhn),
            );
        },
    },
    {
        type: "student_id_list",
        level: "high",
        label: "List of student IDs (roster or gradebook)",
        find(text) {
            // UMD UIDs are 9 digits. One ID could be the uploader's own; three or more next to
            // ID-like wording, or ten or more on separate lines, looks like a roster.
            const ids = uniq([...text.matchAll(/(?<![\d-])\d{9}(?![\d-])/g)].map((m) => m[0]));
            const idWording = /\b(UID|student\s*(id|number|no\.?)|ID\s*#|university\s*id)\b/i.test(text);
            if ((idWording && ids.length >= 3) || ids.length >= 10) return ids;
            return [];
        },
    },
    {
        type: "credential",
        level: "high",
        label: "Private key or cloud credential",
        find(text) {
            const hits = [];
            const patterns = [
                /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
                /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
                /\bASIA[0-9A-Z]{16}\b/g, // AWS temporary key id
                /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub tokens
                /\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{32,}\b/g, // OpenAI / Stripe style secret keys
                /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
            ];
            for (const re of patterns) for (const m of text.matchAll(re)) hits.push(m[0]);
            return uniq(hits);
        },
    },
    {
        type: "answer_key",
        level: "medium",
        label: "Exam or answer key / instructor-only material",
        find(text) {
            const re =
                /\b(answer\s*key|solution\s*key|exam\s*key|key\s*to\s*(the\s*)?(exam|midterm|final|quiz)|instructor'?s?\s*(copy|edition|solutions?|manual|guide)|solutions?\s*manual|grading\s*rubric\s*\(?\s*(instructor|ta)\s*only)\b/gi;
            return uniq([...text.matchAll(re)].map((m) => m[0].toLowerCase().replace(/\s+/g, " ")));
        },
    },
    {
        type: "restricted_marking",
        level: "medium",
        label: "Marked confidential / do not distribute",
        find(text) {
            const re =
                /\b(do\s*not\s*(distribute|share|post|circulate)|not\s*for\s*(distribution|public\s*release)|strictly\s*confidential|confidential\s*[-:–]|for\s*internal\s*use\s*only)\b/gi;
            return uniq([...text.matchAll(re)].map((m) => m[0].toLowerCase().replace(/\s+/g, " ")));
        },
    },
    {
        type: "contact_list",
        level: "medium",
        label: "Many personal emails or phone numbers",
        find(text) {
            const emails = uniq(
                [...text.matchAll(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g)].map((m) =>
                    m[0].toLowerCase(),
                ),
            );
            const phones = uniq(
                [...text.matchAll(/(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)/g)].map((m) =>
                    m[0].replace(/\D/g, ""),
                ),
            );
            return emails.length + phones.length >= 15 ? [...emails, ...phones] : [];
        },
    },
];

/**
 * Scans text and returns { level: "none"|"medium"|"high", findings: [...] }.
 * Each finding: { type, level, label, count, samples } with masked samples.
 */
function scanText(text) {
    const input = (text || "").slice(0, MAX_TEXT);
    const findings = [];
    for (const d of detectors) {
        const hits = d.find(input);
        if (hits.length) {
            findings.push({
                type: d.type,
                level: d.level,
                label: d.label,
                count: hits.length,
                samples: hits.slice(0, 3).map((h) => (d.level === "high" ? mask(h) : h.slice(0, 60))),
            });
        }
    }
    const level = findings.some((f) => f.level === "high")
        ? "high"
        : findings.length
          ? "medium"
          : "none";
    return { level, findings };
}

/**
 * Extracts and scans an upload. status: "clean" | "flagged" | "skipped".
 * Also returns the extracted `text` so the caller can index it (never store it on the file).
 */
async function scanUpload(buffer, mimetype, name) {
    const text = await extractText(buffer, mimetype, name);
    if (text === null) return { status: "skipped", level: "none", findings: [], reason: "unreadable format", text: null };
    const { level, findings } = scanText(text);
    return { status: level === "none" ? "clean" : "flagged", level, findings, text };
}

module.exports = { extractText, readText, scanText, scanUpload, luhn, mask };
