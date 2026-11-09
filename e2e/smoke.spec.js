// Read-only checks (@live): safe to run against production.
const { expect, test } = require("@playwright/test");

test("home, sign-in, sign-up and health check work @live", async ({ page, request }) => {
    const health = await request.get("/health");
    expect(health.status()).toBe(200);
    expect((await health.json()).status).toBe("OK");

    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: /Share Notes/ })).toBeVisible();

    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Login to Terp Notes" })).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();

    await page.goto("/register");
    await expect(page.getByRole("heading", { name: "Join Terp Notes" })).toBeVisible();

    for (const path of ["/privacy", "/terms", "/contact"]) {
        const res = await request.get(path);
        expect(res.status(), path).toBe(200);
    }
});

test("home page works at phone width (390 px) @live", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: /Share Notes/ })).toBeVisible();
    const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);
});
