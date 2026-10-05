import assert from "node:assert/strict";
import test from "node:test";
import { isClearlyCiscoConfiguration } from "./vendor-detection";

test("detects compliant Cisco configuration", () => {
  assert.equal(isClearlyCiscoConfiguration("aaa new-model\nip ssh version 2\nline vty 0 4\n transport input ssh"), true);
});

test("detects non-compliant Cisco configuration", () => {
  assert.equal(isClearlyCiscoConfiguration("aaa new-model\nip ssh version 1\nline vty 0 4\n transport input telnet"), true);
});

test("detects minimal Cisco hostname and interface configuration", () => {
  assert.equal(isClearlyCiscoConfiguration("hostname TEST-ROUTER\ninterface GigabitEthernet0/0\ndescription Management"), true);
});

test("does not classify ambiguous input as Cisco", () => {
  assert.equal(isClearlyCiscoConfiguration("hostname router\ndescription Management"), false);
});
