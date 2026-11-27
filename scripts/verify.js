#!/usr/bin/env node
// Boots terp-notes locally with a throwaway MongoDB and drives the verify flow
// (.claude/skills/verify/SKILL.md). Nothing real is touched: no Atlas, S3, email or VirusTotal.
//
//   npm run verify                     run e2e/verify.spec.js, screenshots in test-results/verify/
//   npm run verify -- e2e/x.spec.js    run other flows against the same throwaway database
//   npm run verify -- --serve          keep the app up at http://127.0.0.1:3311 to look at by hand
//
// Uses MONGO_CONNECTION_STRING if it's already set (CI); otherwise starts an in-memory MongoDB.
// The first run downloads a MongoDB binary (~80 MB) into ~/.cache/mongodb-binaries.
const { spawn } = require("node:child_process");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
const serve = args.includes("--serve");

function run(cmd, cmdArgs, env) {
    return new Promise((resolve) => {
        const child = spawn(cmd, cmdArgs, { cwd: root, env, stdio: "inherit" });
        const stop = () => child.kill("SIGTERM");
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
        child.on("exit", (code, signal) => resolve(code ?? (signal ? 0 : 1)));
    });
}

async function main() {
    let mongo;
    let url = process.env.MONGO_CONNECTION_STRING;
    if (!url) {
        const { MongoMemoryServer } = require("mongodb-memory-server-core");
        mongo = await MongoMemoryServer.create();
        url = mongo.getUri().replace(/\/$/, "");
        console.log(`verify: throwaway MongoDB at ${url}`);
    }
    // NODE_ENV=production in an agent's shell would change how the app runs; the tests set "test".
    process.env.MONGO_CONNECTION_STRING = url; // e2e/helpers reads it when first required
    const env = { ...process.env, NODE_ENV: "test" };
    let code;
    try {
        if (serve) {
            const { seedUser } = require("../e2e/helpers");
            const userid = "verify_student";
            const password = await seedUser({ userid, firstname: "Vera", lastname: "Fy", email: `${userid}@terpmail.umd.edu` });
            console.log(`verify: open http://127.0.0.1:3311/login and sign in as ${userid} / ${password} (Ctrl-C stops)`);
            code = await run(process.execPath, ["server.js"], {
                ...env,
                PORT: "3311",
                MONGO_DB_NAME: "terpnotes_e2e",
                MONGO_FILECOLLECTION: "files",
                MONGO_USERCOLLECTION: "users",
                AWS_ACCESS_KEY_ID: "test",
                AWS_SECRET_ACCESS_KEY: "test",
                AWS_REGION: "us-east-1",
                AWS_S3_BUCKET: "terpnotes-e2e",
                SECRET_KEY: "verify-only-session-secret",
                LOGIN_RATE_LIMIT_MAX: "1000",
            });
        } else {
            const specs = args.length ? args : ["e2e/verify.spec.js"];
            code = await run(process.execPath, [require.resolve("@playwright/test/cli"), "test", ...specs], env);
        }
    } finally {
        await mongo?.stop();
    }
    process.exit(code);
}

main().catch((err) => {
    console.error(`verify: ${err.message}`);
    process.exit(1);
});
