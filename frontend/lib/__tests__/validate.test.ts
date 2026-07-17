import { describe, expect, it } from "vitest";
import { isValidServerFormat } from "../validate";

/**
 * Contract v2 (§3.1, invariant 6): `server` is ONLY a bare IPv4 address or an
 * RFC 1123 hostname — no scheme, no port, no path, no spaces. Mirrors the
 * backend validator (normalize_server in backend/app/api/auth.py).
 */
describe("lib/validate.ts — isValidServerFormat", () => {
  describe("valid IPv4 addresses", () => {
    it.each(["192.168.1.1", "10.0.0.2", "8.8.8.8", "255.255.255.255", "0.0.0.0"])("accepts %s", (value) => {
      expect(isValidServerFormat(value)).toBe(true);
    });
  });

  describe("valid hostnames (RFC 1123)", () => {
    it.each([
      "gateway",
      "ngfw.corp.local",
      "NGFW.Corp.Local", // case-insensitive; backend lowercases
      "my-ngfw.example.com",
      "a.b.c.d.e",
      "host123",
      "1host", // digit-leading label is valid per RFC 1123
    ])("accepts %s", (value) => {
      expect(isValidServerFormat(value)).toBe(true);
    });

    it("accepts surrounding whitespace (trimmed before validation)", () => {
      expect(isValidServerFormat("  192.168.1.1  ")).toBe(true);
    });
  });

  describe("rejected: port", () => {
    it.each(["192.168.1.1:8443", "ngfw.local:8443", "gateway:80"])("rejects %s", (value) => {
      expect(isValidServerFormat(value)).toBe(false);
    });
  });

  describe("rejected: scheme and path", () => {
    it.each(["https://192.168.1.1", "http://ngfw.local", "192.168.1.1/api", "ngfw.local/path/to", "host?query=1", "host#fragment", "host\\backslash"])(
      "rejects %s",
      (value) => {
        expect(isValidServerFormat(value)).toBe(false);
      },
    );
  });

  describe("rejected: spaces and credentials", () => {
    it.each(["not a valid address", "host name.com", "admin@ngfw.local", "user:pass@host"])("rejects %s", (value) => {
      expect(isValidServerFormat(value)).toBe(false);
    });
  });

  describe("rejected: pseudo-IPv4 (octet > 255)", () => {
    it.each(["300.1.2.3", "999.999.999.999", "256.0.0.1", "1.2.3.256"])("rejects %s", (value) => {
      expect(isValidServerFormat(value)).toBe(false);
    });
  });

  describe("rejected: empty / blank / oversized", () => {
    it("rejects empty string", () => {
      expect(isValidServerFormat("")).toBe(false);
    });

    it("rejects whitespace-only string", () => {
      expect(isValidServerFormat("   ")).toBe(false);
    });

    it("rejects a value longer than 253 characters", () => {
      const label = "a".repeat(60);
      const long = Array(5).fill(label).join("."); // 304 chars
      expect(long.length).toBeGreaterThan(253);
      expect(isValidServerFormat(long)).toBe(false);
    });

    it("accepts a hostname at exactly 253 characters", () => {
      // 4 x 62 (61 chars + dot) + 5 chars = 253
      const label61 = "a".repeat(61);
      const host = [label61, label61, label61, label61, "aaaaa"].join(".");
      expect(host.length).toBe(253);
      expect(isValidServerFormat(host)).toBe(true);
    });
  });

  describe("rejected: IPv6 literals (contract v2 — IPv4/hostname only)", () => {
    it.each(["[2001:db8::1]", "2001:db8::1", "::1", "fe80::1%eth0"])("rejects %s", (value) => {
      expect(isValidServerFormat(value)).toBe(false);
    });
  });

  describe("rejected: malformed hostnames", () => {
    it.each([
      "-leading.example.com", // label starts with a hyphen
      "trailing-.example.com", // label ends with a hyphen
      "host_with_underscore", // underscore is not RFC 1123
      "double..dot", // empty label
      ".leadingdot.com", // empty first label
    ])("rejects %s", (value) => {
      expect(isValidServerFormat(value)).toBe(false);
    });

    it("rejects a label longer than 63 characters", () => {
      const longLabel = "a".repeat(64);
      expect(isValidServerFormat(`${longLabel}.com`)).toBe(false);
    });
  });
});
