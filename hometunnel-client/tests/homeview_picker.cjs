const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { join } = require("node:path");
const { createInterface } = require("node:readline");
const { test } = require("node:test");
const { chromium, expect } = require("playwright/test");

async function withPicker(exercise) {
  const server = spawn(process.env.PYTHON || "python3", [join(__dirname, "homeview_browser_fixture.py")], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  const lines = createInterface({ input: server.stdout });
  let browser;
  try {
    const port = await Promise.race([
      once(lines, "line").then(([line]) => Number(line)),
      once(server, "exit").then(([code]) => { throw new Error("Ingress fixture exited with status " + code); }),
    ]);
    const base = "http://127.0.0.1:" + port;
    const control = async (change = {}) => {
      const reply = await fetch(base + "/_test/homeview", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(change),
      });
      assert.equal(reply.status, 200);
      return reply.json();
    };
    browser = await chromium.launch();
    console.log("Chromium " + browser.version());
    const page = await browser.newPage();
    page.setDefaultTimeout(7500);
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    const id = (suffix) => page.locator("#homeview-" + suffix);
    const button = (name) => page.getByRole("button", { name, exact: true });
    const rows = (parent) => id(parent).locator(".homeview-item");
    const row = (text) => rows("entities").filter({ hasText: text });
    const customize = (item) => item.getByLabel("Customize shared label");
    const label = (item) => item.getByLabel("Shared label", { exact: true });
    const review = button("Review sharing");
    const add = button("Add entity");
    const reopen = async () => {
      await page.goto(base);
      await page.getByText("Choose what to monitor").click();
      await expect(review).toBeEnabled();
    };
    const select = async (hint) => {
      const option = id("results").locator("option").filter({ hasText: hint });
      await expect(option).toHaveCount(1);
      await id("results").selectOption(await option.getAttribute("value"));
    };
    const search = async (hint) => {
      const discovery = page.waitForResponse((response) => response.url().includes("/discovery?") &&
        new URL(response.url()).searchParams.get("q") === hint);
      await id("search").fill(hint);
      await discovery;
      await select(hint);
    };
    const addEntity = async (hint) => {
      await search(hint);
      await add.click();
    };
    await reopen();
    await exercise({ id, button, rows, row, customize, label, review, add, reopen, select, search, addEntity, control });
    assert.deepEqual(pageErrors, []);
  } finally {
    await browser?.close();
    server.kill();
    lines.close();
  }
}

function pickerTest(name, exercise) {
  test(name, { timeout: 45_000 }, () => withPicker(exercise));
}

pickerTest("the ingress picker keeps selections across inventory and confirmation expiry",
  async ({ id, button, rows, row, customize, label, review, add, select, search, control }) => {
    await button("Find an entity").click();
    await select("binary_sensor.contact");
    await add.click();
    const contact = row("Entry sensor · A Contact");
    await expect(customize(contact)).not.toBeChecked();
    await expect(label(contact)).toBeDisabled();
    await expect(label(contact)).toHaveValue("Entry sensor");
    await contact.getByLabel("Share open or closed").check();

    await button("Next page").click();
    await select("light.room_5");
    await add.click();
    for (const number of [2, 3, 4]) {
      await search("light.room_" + number);
      await add.click();
    }
    await expect(id("device-count")).toHaveText("5 of 5 devices selected");
    await search("light.room_6");
    await expect(add).toBeDisabled();
    await search("sensor.battery");
    await expect(add).toBeEnabled();
    await add.click();
    const battery = row("Entry sensor · B Battery");
    await customize(battery).check();
    await label(battery).fill("Changed my mind");
    await customize(battery).uncheck();
    await expect(label(battery)).toHaveValue("Entry sensor");
    await customize(battery).check();
    await label(battery).fill("Entry battery");
    await battery.getByLabel("Share battery percentage").check();
    await battery.getByLabel("Low battery threshold (%)").fill("27");
    await expect(id("device-count")).toHaveText("5 of 5 devices selected");
    await search("light.room_6");
    await row("Room 4").getByRole("button", { name: "Remove" }).click();
    await expect(id("device-count")).toHaveText("4 of 5 devices selected");
    await add.click();
    const restricted = row("router.local");
    await expect(id("device-count")).toHaveText("5 of 5 devices selected");

    await id("ha").uncheck();
    const addTcp = button("Add TCP service");
    const addService = async (number) => {
      await addTcp.click();
      const tcp = rows("services").last();
      await label(tcp).fill("Local service " + number);
      await tcp.getByLabel("Private IPv4 address").fill("192.168.1.50");
      await tcp.getByLabel("TCP port").fill(String(8100 + number));
    };
    for (const number of [1, 2, 3]) await addService(number);
    await expect(addTcp).toBeDisabled();
    await expect(id("tcp-count")).toHaveText("3 of 3 services selected");
    await rows("services").last().getByRole("button", { name: "Remove" }).click();
    await expect(id("tcp-count")).toHaveText("2 of 3 services selected");
    await addService(3);

    assert.equal((await control({ advance: 61, down: true })).reads, 1);
    await review.click();
    await expect(id("error")).toContainText("Your draft is still here");
    await expect(row("Room 5")).toHaveCount(1);
    await expect(label(battery)).toHaveValue("Entry battery");
    await expect(rows("services").first().getByLabel("TCP port")).toHaveValue("8101");
    await expect(id("ha")).not.toBeChecked();

    await control({ down: false, name: "Entry renamed" });
    await review.click();
    await expect(restricted.getByRole("alert")).toContainText("Customize shared label");
    await expect(rows("entities").getByRole("alert")).toHaveCount(1);
    await customize(restricted).check();
    await label(restricted).fill("Utility switch");
    await review.click();
    await expect(id("preview")).toBeVisible();
    const ownerLabels = await id("shared").locator("li").allTextContents();
    assert.ok(ownerLabels.includes("Entry renamed · Open or closed"));
    assert.ok(ownerLabels.includes("Entry battery · Battery percentage · threshold 27%"));
    assert.ok(ownerLabels.includes("Room 5 · Available, unavailable or unknown"));
    assert.ok(ownerLabels.includes("Utility switch · Available, unavailable or unknown"));
    assert.ok(ownerLabels.includes("Local service 1 · Local TCP reachability"));
    assert.ok(ownerLabels.every((line) => !line.includes("Home Assistant API")));
    assert.equal((await control()).reads, 3);

    // Refresh only the catalog, then let the original confirmation expire.
    await control({ advance: 90 });
    await search("binary_sensor.contact");
    assert.equal((await control({ advance: 31 })).reads, 4);
    await id("apply").click();
    await expect(id("error")).toContainText("confirmation expired");
    await expect(label(battery)).toHaveValue("Entry battery");
    await expect(battery.getByLabel("Low battery threshold (%)")).toHaveValue("27");
    await expect(rows("services").first().getByLabel("Private IPv4 address")).toHaveValue("192.168.1.50");
    await review.click();
    await expect(id("preview")).toBeVisible();
    assert.deepEqual(await id("shared").locator("li").allTextContents(), ownerLabels);
    await id("apply").click();
    await expect(button("Stop sharing")).toBeVisible();

    await review.click();
    await expect(id("preview")).toBeVisible();
    await control({ repair: true });
    await id("apply").click();
    await expect(id("error")).toContainText("Pairing or settings changed");
});

pickerTest("saved entity hints distinguish siblings with the same approved shared label",
  async ({ id, button, row, label, review, reopen, addEntity }) => {
    await button("Find an entity").click();
    await addEntity("sensor.humidity");
    await addEntity("sensor.temperature");
    await review.click();
    const shared = id("shared").getByText("Entry sensor · Available, unavailable or unknown", { exact: true });
    await expect(shared).toHaveCount(2);
    await id("apply").click();
    await expect(button("Stop sharing")).toBeVisible();
    await reopen();

    const humidity = row("Entry sensor · sensor.humidity");
    const temperature = row("Entry sensor · sensor.temperature");
    await expect(humidity).toBeVisible();
    await expect(temperature).toBeVisible();
    await humidity.getByRole("button", { name: "Remove" }).click();
    await expect(temperature.getByLabel("Share availability")).toBeChecked();
    await expect(label(temperature)).toHaveValue("Entry sensor");
    await review.click();
    await expect(shared).toHaveCount(1);
    await expect(id("shared")).not.toContainText("sensor.temperature");
    await id("apply").click();
    await expect(id("preview")).toBeHidden();
    await reopen();
    await expect(label(temperature)).toHaveValue("Entry sensor");
    await expect(humidity).toHaveCount(0);
});

pickerTest("review flags either FEFF boundary and saved labels stay available for correction",
  async ({ id, button, row, customize, label, review, reopen, addEntity, control }) => {
    await control({ name: "\uFEFFEntry sensor" });
    await button("Find an entity").click();
    await addEntity("binary_sensor.contact");
    await addEntity("light.room_2");
    const contact = row("Entry sensor · A Contact");
    for (const change of [{}, { advance: 61, name: "Entry sensor\uFEFF" }]) {
      await control(change);
      await review.click();
      await expect(contact.getByRole("alert")).toContainText("Customize shared label");
      await expect(row("Room 2").getByRole("alert")).toHaveCount(0);
      await expect(id("preview")).toBeHidden();
    }
    await customize(contact).check();
    await label(contact).fill("Entry contact");
    await review.click();
    await expect(id("shared")).toContainText("Entry contact · Available, unavailable or unknown");
    await id("apply").click();
    await expect(button("Stop sharing")).toBeVisible();

    const oldLabel = "Entry contact\uFEFF";
    await control({ savedLabel: oldLabel });
    await reopen();
    const savedContact = row("binary_sensor.contact");
    await expect(label(savedContact)).toHaveValue(oldLabel);
    await review.click();
    await expect(savedContact.getByRole("alert")).toContainText("leading or trailing whitespace");
    await label(savedContact).fill("Entry contact corrected");
    await review.click();
    await expect(id("shared")).toContainText("Entry contact corrected · Available, unavailable or unknown");
    await id("apply").click();
    await expect(id("preview")).toBeHidden();
    await expect(label(savedContact)).toHaveValue("Entry contact corrected");
});

pickerTest("reactivating an inactive entity follows the device cap immediately",
  async ({ id, button, row, addEntity }) => {
    await button("Find an entity").click();
    await addEntity("binary_sensor.contact");
    for (const number of [2, 3, 4, 5]) await addEntity("light.room_" + number);
    const count = id("device-count");
    await expect(count).toHaveText("5 of 5 devices selected");
    const original = row("Room 5");
    const availability = original.getByLabel("Share availability");
    const lightValue = original.getByLabel("Share light on or off");
    await availability.uncheck();
    await expect(count).toHaveText("4 of 5 devices selected");
    await addEntity("light.room_6");
    await expect(count).toHaveText("5 of 5 devices selected");
    for (const checkbox of [availability, lightValue]) {
      await checkbox.click();
      await expect(checkbox).not.toBeChecked();
      await expect(original.getByRole("alert")).toContainText("Choose up to 5 devices");
      await expect(count).toHaveText("5 of 5 devices selected");
    }
    await addEntity("sensor.battery");
    const batteryAvailability = row("B Battery").getByLabel("Share availability");
    await batteryAvailability.uncheck();
    await batteryAvailability.check();
    await expect(count).toHaveText("5 of 5 devices selected");
    await row("router.local").getByRole("button", { name: "Remove" }).click();
    await expect(count).toHaveText("4 of 5 devices selected");
    await availability.check();
    await expect(availability).toBeChecked();
    await expect(original.getByRole("alert")).toHaveCount(0);
    await expect(count).toHaveText("5 of 5 devices selected");
});
