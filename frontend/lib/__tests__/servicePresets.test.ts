import { describe, expect, it } from "vitest";
import { parseTarget, clampPort, SERVICE_PRESETS } from "../servicePresets";

/**
 * Feature #5: the address field holds only a host; a pasted URL or `host:port`
 * must be reduced to (host, port) so the port lands in the separate port block.
 */
describe("lib/servicePresets.ts — parseTarget", () => {
  it("keeps a bare host and reports no port", () => {
    expect(parseTarget("example.com")).toEqual({ host: "example.com", port: null });
  });

  it("splits host:port", () => {
    expect(parseTarget("example.com:3389")).toEqual({ host: "example.com", port: 3389 });
    expect(parseTarget("192.168.1.10:8443")).toEqual({ host: "192.168.1.10", port: 8443 });
  });

  it("reduces a full URL to its host, dropping scheme, path, query and fragment", () => {
    expect(parseTarget("https://example.com/path?q=1#frag")).toEqual({ host: "example.com", port: null });
    expect(parseTarget("https://sub.example.com:8443/a/b?c=d")).toEqual({ host: "sub.example.com", port: 8443 });
  });

  it("drops URL credentials", () => {
    expect(parseTarget("http://user:pass@host.example:8080/x")).toEqual({ host: "host.example", port: 8080 });
  });

  it("treats an out-of-range port as absent", () => {
    expect(parseTarget("example.com:99999")).toEqual({ host: "example.com", port: null });
    expect(parseTarget("example.com:0")).toEqual({ host: "example.com", port: null });
  });

  it("trims surrounding whitespace and returns empty for blank input", () => {
    expect(parseTarget("  example.com:25  ")).toEqual({ host: "example.com", port: 25 });
    expect(parseTarget("   ")).toEqual({ host: "", port: null });
  });

  it("maps every preset port back through the range clamp", () => {
    for (const preset of SERVICE_PRESETS) {
      expect(clampPort(preset.port)).toBe(preset.port);
    }
  });
});
