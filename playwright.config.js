// End-to-end tests (see factory skills/integration-tests).
// - default: starts the app locally with test settings. CI provides MongoDB as a service.
// - live: `BASE_URL=https://terp-notes.org npm run test:live` runs only the read-only
//   @live tests against production, without starting anything locally.
const { defineConfig } = require("@playwright/test");

const live = process.env.BASE_URL;
const port = 3311;

module.exports = defineConfig({
    testDir: "e2e",
    timeout: 30_000,
    retries: live ? 1 : 0,
    workers: 1,
    use: {
        baseURL: live || `http://127.0.0.1:${port}`,
        ...(process.env.CHROME_PATH
            ? { launchOptions: { executablePath: process.env.CHROME_PATH } }
            : {}),
    },
    ...(live
        ? {}
        : {
              webServer: {
                  command: "node server.js",
                  url: `http://127.0.0.1:${port}/health`,
                  reuseExistingServer: false,
                  timeout: 60_000,
                  // Test-only values. S3, email and VirusTotal are never called in these flows.
                  env: {
                      PORT: String(port),
                      MONGO_CONNECTION_STRING:
                          process.env.MONGO_CONNECTION_STRING || "mongodb://127.0.0.1:27017",
                      MONGO_DB_NAME: "terpnotes_e2e",
                      MONGO_FILECOLLECTION: "files",
                      MONGO_USERCOLLECTION: "users",
                      AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || "test",
                      AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || "test",
                      AWS_REGION: "us-east-1",
                      AWS_S3_BUCKET: process.env.AWS_S3_BUCKET || "terpnotes-e2e",
                      ...(process.env.AWS_S3_ENDPOINT ? { AWS_S3_ENDPOINT: process.env.AWS_S3_ENDPOINT } : {}),
                      SECRET_KEY: "e2e-only-session-secret",
                      NODE_ENV: "test",
                  },
              },
          }),
});
