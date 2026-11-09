// A stand-in for an OpenAI-compatible chat API, for end-to-end tests only.
// It answers with the first source title it was given, so the test can see notes reached it.
const http = require("http");

const port = Number(process.env.MOCK_LLM_PORT || 3399);
http.createServer((req, res) => {
    if (req.method === "GET") return res.end("mock llm ok");
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
        const { messages = [] } = JSON.parse(body || "{}");
        const user = messages.find((m) => m.role === "user")?.content || "";
        const source = (user.match(/\[1\] ([^\n]+)/) || [])[1] || "no sources";
        const quiz = /practice quiz/.test(user);
        const content = quiz
            ? `1. What does LIFO stand for? (mock quiz from ${source})\n\nAnswer key: 1. Last in, first out [1]`
            : `Mock answer based on ${source} [1].`;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content } }] }));
    });
}).listen(port, "127.0.0.1", () => console.log(`mock llm on ${port}`));
