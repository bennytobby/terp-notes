const { expect, test } = require("@playwright/test");
const { needsDb, seedUser, withDb } = require("./helpers");
const { indexFile } = require("../utils/study-buddy");

test.skip(needsDb, "needs a test MongoDB");

test("a signed-in student can generate a cited quiz without typing a question", async ({ request }) => {
    const user = { userid: "e2e_quiz_api", email: "e2e_quiz_api@terpmail.umd.edu" };
    const password = await seedUser(user);
    const input = { classCode: "MATH240", mode: "quiz" };
    expect((await request.post("/api/study/ask", { data: input })).status()).toBe(401);
    const login = await request.post("/loginSubmit", { form: { userid: user.userid, password }, maxRedirects: 0 });
    expect(login.headers().location).toBe("/dashboard");

    const file = { classCode: "MATH240", originalName: "linear-algebra.txt", filename: "e2e-linear-algebra.txt", school: "umd", uploadedBy: user.userid };
    await withDb(async db => {
        await db.collection("studyUsage").deleteMany({ userid: user.userid });
        await db.collection("files").deleteMany({ filename: file.filename });
        await db.collection("noteTexts").deleteMany({ filename: file.filename });
        const { insertedId } = await db.collection("files").insertOne(file);
        await indexFile(db, { ...file, _id: insertedId }, "A basis is a linearly independent set that spans a vector space.");
    });
    const context = await (await request.get("/api/study/context?course=MATH240")).json();
    expect(context.files).toEqual(expect.arrayContaining([expect.objectContaining({ filename: file.filename })]));
    const response = await request.post("/api/study/ask", { data: { ...input, files: [file.filename] } });
    expect(response.ok()).toBe(true);
    const result = await response.json();
    expect(result).toMatchObject({ mode: "ai", kind: "quiz", sources: [{ n: 1, filename: file.filename }] });
    expect(result.answer).toContain("mock quiz from linear-algebra.txt");
    expect(result.answer).toMatch(/## Answer key\n1\..*\[1\]/);
});
