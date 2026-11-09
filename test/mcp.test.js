const assert = require("node:assert/strict");
const { test } = require("node:test");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = require("@modelcontextprotocol/sdk/inMemory.js");
const mcp = require("../utils/mcp");
const sb = require("../utils/study-buddy");
const { fakeDb } = require("./fake-db");

async function setup() {
    const db = fakeDb();
    await db.collection("users").insertOne({ userid: "stu", role: "contributor", firstname: "Stu" });
    await db.collection("users").insertOne({ userid: "banned", role: "contributor", isBanned: true });
    const files = db.collection("files");
    const a = await files.insertOne({ classCode: "CMSC132", originalName: "stacks.txt", filename: "k1", uploadedBy: "x" });
    const b = await files.insertOne({ classCode: "CMSC132", originalName: "roster.txt", filename: "k2", uploadedBy: "x", quarantined: true });
    const c = await files.insertOne({ classCode: "MATH140", originalName: "limits.txt", filename: "k3", uploadedBy: "x" });
    await sb.indexFile(db, { _id: a.insertedId, classCode: "CMSC132", originalName: "stacks.txt", filename: "k1" }, "A stack is last-in first-out. Push and pop use the top.");
    await sb.indexFile(db, { _id: b.insertedId, classCode: "CMSC132", originalName: "roster.txt", filename: "k2" }, "Stack push pop roster that is held for review.");
    await sb.indexFile(db, { _id: c.insertedId, classCode: "MATH140", originalName: "limits.txt", filename: "k3" }, "A limit describes the value a function approaches.");
    return { db, ids: { a: String(a.insertedId), b: String(b.insertedId) } };
}

async function connect(db, user) {
    const server = mcp.buildServer({ db, filesCollection: "files", baseUrl: "https://terp-notes.test", user });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    await server.connect(serverT);
    const client = new Client({ name: "test", version: "1" });
    await client.connect(clientT);
    return client;
}

const parse = (r) => JSON.parse(r.content[0].text);

test("tokens are stored hashed, authenticate their owner, and can be revoked", async () => {
    const { db } = await setup();
    const { token, id } = await mcp.createToken(db, "stu", "ChatGPT");
    assert.match(token, mcp.TOKEN_RE);
    assert.ok(!JSON.stringify(db.collection("apiTokens").docs).includes(token));
    const user = await mcp.authenticate(db, "users", token);
    assert.equal(user.userid, "stu");
    assert.ok(db.collection("apiTokens").docs[0].lastUsedAt);
    assert.equal(await mcp.authenticate(db, "users", "tn_" + "0".repeat(40)), null);
    assert.equal(await mcp.authenticate(db, "users", "not-a-token"), null);
    await mcp.revokeToken(db, "stu", id);
    assert.equal(await mcp.authenticate(db, "users", token), null);
    await assert.rejects(mcp.revokeToken(db, "someone-else", id), /not found/);

    const banned = await mcp.createToken(db, "banned", "x");
    assert.equal(await mcp.authenticate(db, "users", banned.token), null, "banned users are refused");
});

test("the token comes from the Bearer header or the URL", () => {
    assert.equal(mcp.tokenFromRequest({ headers: { authorization: "Bearer tn_abc" }, params: {} }), "tn_abc");
    assert.equal(mcp.tokenFromRequest({ headers: {}, params: { token: "tn_xyz" } }), "tn_xyz");
    assert.equal(mcp.tokenFromRequest({ headers: {}, params: {} }), null);
});

test("MCP tools list, search and read notes, never returning held files", async () => {
    const { db, ids } = await setup();
    const client = await connect(db, { userid: "stu", role: "contributor" });
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), ["fetch", "get_note", "list_courses", "search", "search_notes"]);
    assert.ok(tools.every((t) => t.annotations?.readOnlyHint), "all tools are read-only");

    assert.deepEqual(parse(await client.callTool({ name: "list_courses", arguments: {} })), [
        { course: "CMSC132", notes_count: 1 },
        { course: "MATH140", notes_count: 1 },
    ]);

    const hits = parse(await client.callTool({ name: "search_notes", arguments: { query: "stack push pop", course: "cmsc132" } }));
    assert.equal(hits.length, 1);
    assert.equal(hits[0].title, "stacks.txt");
    assert.equal(hits[0].url, "https://terp-notes.test/download/k1");

    const note = parse(await client.callTool({ name: "get_note", arguments: { note_id: ids.a } }));
    assert.match(note.text, /last-in first-out/);
    const held = await client.callTool({ name: "get_note", arguments: { note_id: ids.b } });
    assert.equal(held.isError, true);

    const { results } = parse(await client.callTool({ name: "search", arguments: { query: "stack" } }));
    assert.deepEqual(results.map((r) => r.title), ["CMSC132: stacks.txt"]);
    const doc = parse(await client.callTool({ name: "fetch", arguments: { id: results[0].id } }));
    assert.equal(doc.metadata.course, "CMSC132");

    const bad = await client.callTool({ name: "search_notes", arguments: { query: "x" } });
    assert.equal(bad.isError, true, "input is validated");
});

test("the uploader still sees their own held file", async () => {
    const { db, ids } = await setup();
    db.collection("files").docs.find((d) => String(d._id) === ids.b).uploadedBy = "stu";
    const client = await connect(db, { userid: "stu", role: "contributor" });
    const note = parse(await client.callTool({ name: "get_note", arguments: { note_id: ids.b } }));
    assert.equal(note.title, "roster.txt");
});
