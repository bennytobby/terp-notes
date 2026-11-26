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
        const user = messages.filter((m) => m.role === "user").at(-1)?.content || "";
        const source = (user.match(/\[1\] ([^\n]+)/) || [])[1] || "no sources";
        const quiz = /practice quiz/.test(user);
        const sheet = /cheat sheet/.test(user);
        const exam = user.startsWith("Write a practice exam");
        const content = exam
            ? `## Questions\n1. What does LIFO stand for? (mock exam from ${source})\n2. What does FIFO stand for?\n3. Where does push add?\n4. Where does pop remove?\n5. How does a queue differ from a stack?\n6. When would you use a stack?\n7. When would you use a queue?\n8. Trace two pushes followed by a pop.\n\n## Answer key\n1. Last in, first out [1]\n2. First in, first out [1]\n3. The top [1]\n4. The top [1]\n5. A queue removes the oldest item first [1]\n6. To undo recent actions [1]\n7. To process tasks in arrival order [1]\n8. The pop removes the second item pushed [1]`
            : quiz
            ? `## Questions\n1. What does LIFO stand for? (mock quiz from ${source})\n2. What does FIFO stand for?\n3. Where does push add?\n4. Where does pop remove?\n5. Which order does a queue use?\n\n## Answer key\n1. Last in, first out [1]\n2. First in, first out [1]\n3. The top [1]\n4. The top [1]\n5. First in, first out [1]`
            : sheet
              ? `## Stacks (mock cheat sheet from ${source})\n- **LIFO**: last in, first out [1]`
              : `Mock answer based on ${source} [1].`;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content } }] }));
    });
}).listen(port, "127.0.0.1", () => console.log(`mock llm on ${port}`));
