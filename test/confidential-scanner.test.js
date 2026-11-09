// Unit tests: node --test test/
const assert = require("node:assert/strict");
const { test } = require("node:test");
const archiver = require("archiver");
const { scanText, scanUpload, luhn, mask } = require("../utils/confidential-scanner");

const types = (r) => r.findings.map((f) => f.type).sort();

test("ordinary lecture notes are clean", () => {
    const notes = `CMSC131 Lecture 4 - Loops
    Office hours: Prof. Smith, smith@cs.umd.edu, (301) 405-1000, IRB 1234.
    for (int i = 0; i < 10; i++) { sum += i; } // runs 10 times
    Exam 1 is on 10/14. Review sheet on page 123456789? no, page 12.
    The keyboard key bindings are in Appendix B. Phone extension 555-0199.`;
    const r = scanText(notes);
    assert.equal(r.level, "none", JSON.stringify(r.findings));
});

test("a Social Security number is high and masked", () => {
    const r = scanText("Applicant SSN: 123-45-6789");
    assert.equal(r.level, "high");
    assert.deepEqual(types(r), ["ssn"]);
    assert.equal(r.findings[0].samples[0], "*******6789");
    assert.ok(!JSON.stringify(r).includes("123-45-6789"));
});

test("invalid SSN shapes are ignored", () => {
    assert.equal(scanText("000-12-3456 666-12-3456 900-12-3456 123-00-4567 123-45-0000").level, "none");
});

test("payment cards must pass Luhn and look like a card", () => {
    assert.equal(luhn("4111111111111111"), true);
    assert.equal(luhn("4111111111111112"), false);
    assert.equal(scanText("Card: 4111 1111 1111 1111").level, "high");
    assert.equal(scanText("Order 4111 1111 1111 1112").level, "none");
    assert.equal(scanText("ISBN 9780134685991 and 1234567890123").level, "none");
});

test("one student ID is fine, a roster is high", () => {
    assert.equal(scanText("My UID is 117654321 for the lab sign-up.").level, "none");
    const roster = ["Name, UID, Score", "Alice, 117000001, 92", "Bob, 117000002, 85", "Cara, 117000003, 77"].join("\n");
    const r = scanText(roster);
    assert.equal(r.level, "high");
    assert.deepEqual(types(r), ["student_id_list"]);
    assert.equal(r.findings[0].count, 3);
});

test("private keys and cloud credentials are high", () => {
    const r = scanText("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\nAWS key AKIAIOSFODNN7EXAMPLE");
    assert.equal(r.level, "high");
    assert.deepEqual(types(r), ["credential"]);
    assert.equal(r.findings[0].count, 2);
});

test("answer keys and restricted markings are medium", () => {
    const r = scanText("CMSC216 Midterm 2 - ANSWER KEY\nInstructor copy. Do not distribute.");
    assert.equal(r.level, "medium");
    assert.deepEqual(types(r), ["answer_key", "restricted_marking"]);
});

test("a long contact list is medium, a few contacts are not", () => {
    const few = "a@x.com b@x.com (301) 555-1234";
    assert.equal(scanText(few).level, "none");
    const many = Array.from({ length: 16 }, (_, i) => `student${i}@terpmail.umd.edu`).join("\n");
    assert.equal(scanText(many).level, "medium");
});

test("mask keeps only the last characters", () => {
    assert.equal(mask("4111 1111 1111 1111"), "********1111");
    assert.equal(mask("12"), "**");
});

function minimalPdf(text) {
    const objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        null,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ];
    const stream = `BT /F1 12 Tf 72 720 Td (${text}) Tj ET`;
    objs[3] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
    let out = "%PDF-1.4\n";
    const offsets = [];
    objs.forEach((o, i) => {
        offsets.push(out.length);
        out += `${i + 1} 0 obj\n${o}\nendobj\n`;
    });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
    for (const off of offsets) out += `${String(off).padStart(10, "0")} 00000 n \n`;
    out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(out, "latin1");
}

function minimalDocx(text) {
    return new Promise((resolve, reject) => {
        const zip = archiver("zip");
        const chunks = [];
        zip.on("data", (c) => chunks.push(c));
        zip.on("end", () => resolve(Buffer.concat(chunks)));
        zip.on("error", reject);
        zip.append(
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            { name: "[Content_Types].xml" },
        );
        zip.append(
            '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            { name: "_rels/.rels" },
        );
        zip.append(
            `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:body></w:document>`,
            { name: "word/document.xml" },
        );
        zip.finalize();
    });
}

test("text is extracted from PDF and Word files before scanning", async () => {
    const pdf = await scanUpload(minimalPdf("Applicant SSN 123-45-6789"), "application/pdf", "form.pdf");
    assert.equal(pdf.status, "flagged");
    assert.equal(pdf.level, "high");

    const docx = await scanUpload(
        await minimalDocx("Final exam answer key"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "key.docx",
    );
    assert.equal(docx.status, "flagged");
    assert.equal(docx.level, "medium");

    const clean = await scanUpload(Buffer.from("Week 3: recursion"), "text/plain", "w3.txt");
    assert.equal(clean.status, "clean");
});

test("images and broken files are skipped, not failed", async () => {
    const img = await scanUpload(Buffer.from([0x89, 0x50, 0x4e, 0x47]), "image/png", "x.png");
    assert.equal(img.status, "skipped");
    const broken = await scanUpload(Buffer.from("not a pdf"), "application/pdf", "bad.pdf");
    assert.equal(broken.status, "skipped");
});
