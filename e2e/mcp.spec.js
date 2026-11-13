// MCP server: a student creates a token, an MCP client connects over HTTP (header and private
// URL), searches and reads notes, never sees held files, and loses access when the token is revoked.
// Needs MongoDB (CI).
const { expect, test } = require("@playwright/test");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { StreamableHTTPClientTransport } = require("@modelcontextprotocol/sdk/client/streamableHttp.js");
const { needsDb, seedUser, signIn, withDb } = require("./helpers");

test.skip(needsDb, "needs MongoDB");

const student = { userid: "e2e_mcp", firstname: "Mia", lastname: "Cp", email: "e2e_mcp@terpmail.umd.edu" };

async function mcpClient(url, token) {
    const transport = new StreamableHTTPClientTransport(new URL(url), token ? { requestInit: { headers: { Authorization: `Bearer ${token}` } } } : undefined);
    const client = new Client({ name: "e2e", version: "1.0.0" });
    await client.connect(transport);
    return client;
}

const parse = (r) => JSON.parse(r.content[0].text);

test("a student connects an AI app to their notes over MCP", async ({ page, baseURL }) => {
    const pw = await seedUser(student);
    const ids = await withDb(async (db) => {
        await db.collection("apiTokens").deleteMany({ userid: student.userid });
        await db.collection("noteTexts").deleteMany({ classCode: "CMSC216" });
        await db.collection("files").deleteMany({ classCode: "CMSC216" });
        const base = { classCode: "CMSC216", uploadedBy: "someone", uploadDate: new Date(), mimetype: "text/plain", size: 1, major: "CMSC" };
        const ok = await db.collection("files").insertOne({ ...base, originalName: "pointers.txt", filename: "e2e_pointers.txt", fileHash: "a".repeat(64) });
        const held = await db.collection("files").insertOne({ ...base, originalName: "grades.txt", filename: "e2e_grades.txt", fileHash: "b".repeat(64), quarantined: true });
        await db.collection("noteTexts").insertMany([
            { fileId: String(ok.insertedId), classCode: "CMSC216", originalName: "pointers.txt", filename: "e2e_pointers.txt", chunks: ["A pointer stores a memory address. Dereference it with *p to read the value."], indexedAt: new Date() },
            { fileId: String(held.insertedId), classCode: "CMSC216", originalName: "grades.txt", filename: "e2e_grades.txt", chunks: ["pointer pointer pointer held for review"], indexedAt: new Date() },
        ]);
        return { ok: String(ok.insertedId), held: String(held.insertedId) };
    });

    // Create a token on the AI apps tab in Settings.
    await signIn(page, student.userid, pw);
    await page.goto("/settings");
    await page.getByRole("navigation", { name: "Settings" }).getByRole("link", { name: "AI apps" }).click();
    await page.getByLabel("Token name").fill("E2E client");
    const [created] = await Promise.all([
        page.waitForResponse((r) => r.url().endsWith("/api/ai-access/tokens") && r.request().method() === "POST"),
        page.getByRole("button", { name: "Create token" }).click(),
    ]);
    expect(created.status()).toBe(200);
    await expect(page.locator("#token-value")).toHaveText(/^tn_[a-f0-9]{40}$/);
    const token = (await page.locator("#token-value").textContent()).trim();
    const privateUrl = (await page.locator("#token-url").textContent()).trim();
    expect(token).toMatch(/^tn_[a-f0-9]{40}$/);
    expect(privateUrl).toBe(`${baseURL}/mcp/${token}`);

    // No token: refused.
    const anon = await page.request.post("/mcp", {
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        data: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } },
    });
    expect(anon.status()).toBe(401);

    // Bearer header (Claude Code style).
    const c1 = await mcpClient(`${baseURL}/mcp`, token);
    const { tools } = await c1.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["fetch", "get_note", "list_courses", "search", "search_notes"]);
    const hits = parse(await c1.callTool({ name: "search_notes", arguments: { query: "pointer memory address", course: "CMSC216" } }));
    expect(hits.map((h) => h.title)).toEqual(["pointers.txt"]);
    expect(hits[0].url).toBe(`${baseURL}/download/e2e_pointers.txt`);
    expect((await c1.callTool({ name: "get_note", arguments: { note_id: ids.held } })).isError).toBe(true);
    await c1.close();

    // Private URL (ChatGPT / Claude.ai "No authentication" style).
    const c2 = await mcpClient(privateUrl);
    const courses = parse(await c2.callTool({ name: "list_courses", arguments: {} }));
    expect(courses).toContainEqual({ course: "CMSC216", notes_count: 1 });
    const fetched = parse(await c2.callTool({ name: "fetch", arguments: { id: ids.ok } }));
    expect(fetched.text).toContain("Dereference it with *p");
    await c2.close();

    // The page shows when the token was last used; revoking cuts access.
    await page.reload();
    await expect(page.locator(".token-row", { hasText: "E2E client" })).toContainText("last used");
    page.on("dialog", (d) => d.accept());
    await page.locator(".token-row", { hasText: "E2E client" }).getByRole("button", { name: "Revoke" }).click();
    await expect(page.locator(".token-row", { hasText: "E2E client" })).toHaveCount(0);
    await expect(mcpClient(`${baseURL}/mcp`, token)).rejects.toThrow();
});
