import { test } from "node:test";
import assert from "node:assert/strict";
import { sha1Hex, check } from "./check.js";

test("hashes like the Go version", async () => {
  assert.equal(await sha1Hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
});

test("sends only the prefix and matches locally", async () => {
  let url;
  const fake = async u => { url = u; return { ok: true, text: async () => "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n" }; };
  assert.equal(await check("password", fake), 42);
  assert.ok(url.endsWith("/range/5BAA6"));
  assert.equal(await check("something else", fake), 0);
});
