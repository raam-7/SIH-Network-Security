import assert from "node:assert/strict";
import test from "node:test";
import { vendorOptions } from "./vendors";

test("vendor selector exposes Palo Alto with the backend canonical identifier", () => {
  assert.deepEqual(vendorOptions.find(option => option.label === "Palo Alto PAN-OS"), { value: "palo_alto", label: "Palo Alto PAN-OS" });
});

test("vendor selector retains Auto Detect and existing vendors", () => {
  assert.deepEqual(vendorOptions.map(option => option.value), ["auto", "cisco", "juniper", "fortigate", "palo_alto"]);
});
