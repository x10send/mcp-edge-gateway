import assert from "node:assert/strict";
import test from "node:test";
import {
  isPrivateNetworkAddress,
  isSpecialUseNetworkAddress,
} from "../src/config.js";
import { selectPrivateLookupAddress } from "../src/upstream-dispatcher.js";

test("isPrivateNetworkAddress: RFC-1918 and IPv6 ULA are private", () => {
  assert.equal(isPrivateNetworkAddress("10.0.0.28"), true);
  assert.equal(isPrivateNetworkAddress("10.255.255.255"), true);
  assert.equal(isPrivateNetworkAddress("172.16.0.1"), true);
  assert.equal(isPrivateNetworkAddress("172.31.255.255"), true);
  assert.equal(isPrivateNetworkAddress("192.168.1.1"), true);
  assert.equal(isPrivateNetworkAddress("192.168.255.255"), true);
  assert.equal(isPrivateNetworkAddress("fd00::1"), true);
  assert.equal(isPrivateNetworkAddress("fc00::1"), true);
});

test("isPrivateNetworkAddress: loopback and link-local are not private LAN addresses", () => {
  // These are special-use, not safe LAN backends — use isSpecialUseNetworkAddress to check them
  assert.equal(isPrivateNetworkAddress("127.0.0.1"), false);
  assert.equal(isPrivateNetworkAddress("169.254.169.254"), false);
  assert.equal(isPrivateNetworkAddress("::1"), false);
  assert.equal(isPrivateNetworkAddress("fe80::1"), false);
});

test("isPrivateNetworkAddress: public and documentation addresses are not private", () => {
  assert.equal(isPrivateNetworkAddress("203.0.113.10"), false, "TEST-NET-3");
  assert.equal(isPrivateNetworkAddress("8.8.8.8"), false, "Google DNS");
  assert.equal(isPrivateNetworkAddress("1.1.1.1"), false, "Cloudflare DNS");
  assert.equal(
    isPrivateNetworkAddress("2001:db8::1"),
    false,
    "documentation IPv6",
  );
});

test("isSpecialUseNetworkAddress: IPv4 loopback range", () => {
  assert.equal(isSpecialUseNetworkAddress("127.0.0.1"), true);
  assert.equal(isSpecialUseNetworkAddress("127.0.0.2"), true);
  assert.equal(isSpecialUseNetworkAddress("127.255.255.255"), true);
});

test("isSpecialUseNetworkAddress: IPv4 link-local range (including AWS metadata)", () => {
  assert.equal(isSpecialUseNetworkAddress("169.254.0.1"), true);
  assert.equal(
    isSpecialUseNetworkAddress("169.254.169.254"),
    true,
    "AWS metadata service",
  );
  assert.equal(isSpecialUseNetworkAddress("169.254.255.255"), true);
});

test("isSpecialUseNetworkAddress: IPv6 loopback and link-local", () => {
  assert.equal(isSpecialUseNetworkAddress("::1"), true);
  assert.equal(isSpecialUseNetworkAddress("fe80::1"), true);
  assert.equal(
    isSpecialUseNetworkAddress("fe80::1%eth0"),
    true,
    "scoped link-local",
  );
});

test("isSpecialUseNetworkAddress: IPv4-mapped IPv6 loopback and link-local", () => {
  assert.equal(
    isSpecialUseNetworkAddress("::ffff:127.0.0.1"),
    true,
    "IPv4-mapped loopback",
  );
  assert.equal(
    isSpecialUseNetworkAddress("::ffff:127.255.255.255"),
    true,
    "IPv4-mapped loopback high end",
  );
  assert.equal(
    isSpecialUseNetworkAddress("::ffff:169.254.169.254"),
    true,
    "IPv4-mapped AWS metadata service",
  );
  assert.equal(
    isSpecialUseNetworkAddress("::ffff:0.0.0.0"),
    true,
    "IPv4-mapped unspecified",
  );
});

test("isSpecialUseNetworkAddress: IPv4 unspecified address", () => {
  assert.equal(
    isSpecialUseNetworkAddress("0.0.0.0"),
    true,
    "unspecified routes to loopback on Linux",
  );
});

test("isSpecialUseNetworkAddress: RFC-1918 and public addresses are not special-use", () => {
  assert.equal(isSpecialUseNetworkAddress("10.0.0.1"), false);
  assert.equal(isSpecialUseNetworkAddress("192.168.1.1"), false);
  assert.equal(isSpecialUseNetworkAddress("8.8.8.8"), false);
  assert.equal(isSpecialUseNetworkAddress("fd00::1"), false);
  assert.equal(
    isSpecialUseNetworkAddress("::ffff:10.0.0.1"),
    false,
    "IPv4-mapped private is not special-use",
  );
  assert.equal(
    isSpecialUseNetworkAddress("::ffff:8.8.8.8"),
    false,
    "IPv4-mapped public is not special-use",
  );
});

test("DNS selection uses only private network addresses", () => {
  assert.deepEqual(
    selectPrivateLookupAddress([
      { address: "203.0.113.10", family: 4 },
      { address: "10.0.0.28", family: 4 },
    ]),
    { address: "10.0.0.28", family: 4 },
  );
});

test("DNS selection rejects loopback and link-local addresses", () => {
  assert.equal(
    selectPrivateLookupAddress([{ address: "127.0.0.1", family: 4 }]),
    undefined,
    "IPv4 loopback must be rejected",
  );
  assert.equal(
    selectPrivateLookupAddress([{ address: "::1", family: 6 }]),
    undefined,
    "IPv6 loopback must be rejected",
  );
  assert.equal(
    selectPrivateLookupAddress([{ address: "169.254.169.254", family: 4 }]),
    undefined,
    "AWS metadata service must be rejected",
  );
  assert.equal(
    selectPrivateLookupAddress([{ address: "fe80::1", family: 6 }]),
    undefined,
    "IPv6 link-local must be rejected",
  );
  assert.equal(
    selectPrivateLookupAddress([{ address: "224.0.0.1", family: 4 }]),
    undefined,
    "multicast must be rejected",
  );
});

test("DNS selection prefers the first private address when multiple are available", () => {
  assert.deepEqual(
    selectPrivateLookupAddress([
      { address: "10.0.0.1", family: 4 },
      { address: "192.168.1.1", family: 4 },
    ]),
    { address: "10.0.0.1", family: 4 },
  );
});

test("DNS selection skips loopback and selects a valid private address in mixed list", () => {
  assert.deepEqual(
    selectPrivateLookupAddress([
      { address: "127.0.0.1", family: 4 },
      { address: "10.0.0.1", family: 4 },
    ]),
    { address: "10.0.0.1", family: 4 },
    "should skip loopback and select the RFC-1918 address",
  );
});
