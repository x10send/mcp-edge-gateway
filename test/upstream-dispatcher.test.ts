import assert from "node:assert/strict";
import test from "node:test";
import { isPrivateNetworkAddress } from "../src/config.js";
import { selectPrivateLookupAddress } from "../src/upstream-dispatcher.js";

test("private network address checks reject public and special-use addresses", () => {
  assert.equal(isPrivateNetworkAddress("10.0.0.28"), true);
  assert.equal(isPrivateNetworkAddress("172.16.0.1"), true);
  assert.equal(isPrivateNetworkAddress("192.168.1.1"), true);
  assert.equal(isPrivateNetworkAddress("fd00::1"), true);

  assert.equal(isPrivateNetworkAddress("127.0.0.1"), false);
  assert.equal(isPrivateNetworkAddress("169.254.169.254"), false);
  assert.equal(isPrivateNetworkAddress("203.0.113.10"), false);
  assert.equal(isPrivateNetworkAddress("::1"), false);
});

test("DNS selection uses only private network addresses", () => {
  assert.deepEqual(
    selectPrivateLookupAddress([
      { address: "203.0.113.10", family: 4 },
      { address: "10.0.0.28", family: 4 },
    ]),
    { address: "10.0.0.28", family: 4 },
  );
  assert.equal(
    selectPrivateLookupAddress([{ address: "169.254.169.254", family: 4 }]),
    undefined,
  );
});
