import { lookup } from "node:dns";
import type { LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";
import { Agent } from "undici";
import { isPrivateNetworkAddress, type SecurityConfig } from "./config.js";

export function createUpstreamDispatcher(security: SecurityConfig): Agent {
  return new Agent({
    connect: {
      timeout: security.upstreamConnectTimeoutMs,
      lookup: security.allowPrivateUpstreamsOnly ? privateLookup : undefined,
    },
    headersTimeout: security.upstreamHeadersTimeoutMs,
    bodyTimeout: security.upstreamBodyTimeoutMs,
    maxHeaderSize: security.upstreamResponseHeaderLimitBytes,
  });
}

const privateLookup: LookupFunction = (hostname, _options, callback): void => {
  lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
    if (error) {
      callback(error, "", 0);
      return;
    }

    const safeAddress = selectPrivateLookupAddress(addresses);
    if (!safeAddress) {
      callback(
        new Error(`Upstream hostname ${hostname} did not resolve privately`),
        "",
        0,
      );
      return;
    }

    callback(null, safeAddress.address, safeAddress.family);
  });
};

function isPrivateLookupAddress(address: LookupAddress): boolean {
  return isPrivateNetworkAddress(address.address);
}

export function selectPrivateLookupAddress(
  addresses: LookupAddress[],
): LookupAddress | undefined {
  return addresses.find(isPrivateLookupAddress);
}
