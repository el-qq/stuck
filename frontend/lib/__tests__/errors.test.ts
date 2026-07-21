import { describe, it, expect, vi } from "vitest";
import { ApiError, logApiError, normalizeErrorCode, isApiError, toApiError } from "../errors";

describe("lib/errors.ts", () => {
  describe("ApiError class", () => {
    it("creates an ApiError with code and message", () => {
      const err = new ApiError("server_unreachable", "Connection failed");
      expect(err.code).toBe("server_unreachable");
      expect(err.message).toBe("Connection failed");
      expect(err.name).toBe("ApiError");
    });

    it("includes optional HTTP status and details", () => {
      const details = { host: "example.com" };
      const err = new ApiError("server_unreachable", "Failed", {
        httpStatus: 502,
        details,
      });
      expect(err.httpStatus).toBe(502);
      expect(err.details).toEqual(details);
    });
  });

  describe("normalizeErrorCode", () => {
    it("accepts known error codes", () => {
      const knownCodes = [
        "validation_error",
        "invalid_server_address",
        "ngfw_host_not_allowed",
        "invalid_credentials",
        "second_factor_required",
        "insufficient_ngfw_permissions",
        "not_authenticated",
        "session_expired",
        "server_unreachable",
        "api_changed",
        "ngfw_error",
        "not_found",
        "internal_error",
      ];

      for (const code of knownCodes) {
        expect(normalizeErrorCode(code)).toBe(code);
      }
    });

    it("returns ngfw_error for unknown codes", () => {
      expect(normalizeErrorCode("unknown_code")).toBe("ngfw_error");
      expect(normalizeErrorCode("random_error")).toBe("ngfw_error");
    });

    it("returns ngfw_error for null/undefined", () => {
      expect(normalizeErrorCode(null)).toBe("ngfw_error");
      expect(normalizeErrorCode(undefined)).toBe("ngfw_error");
    });

    it("returns ngfw_error for empty string", () => {
      expect(normalizeErrorCode("")).toBe("ngfw_error");
    });
  });

  describe("isApiError", () => {
    it("returns true for ApiError instances", () => {
      const err = new ApiError("server_unreachable", "test");
      expect(isApiError(err)).toBe(true);
    });

    it("returns false for other Error types", () => {
      const err = new Error("generic error");
      expect(isApiError(err)).toBe(false);
    });

    it("returns false for non-Error objects", () => {
      expect(isApiError({ code: "server_unreachable" })).toBe(false);
      expect(isApiError("error string")).toBe(false);
      expect(isApiError(null)).toBe(false);
    });
  });

  describe("toApiError", () => {
    it("returns ApiError as-is", () => {
      const original = new ApiError("server_unreachable", "test");
      const result = toApiError(original);
      expect(result).toBe(original);
    });

    it("converts Error to ApiError", () => {
      const err = new Error("something broke");
      const result = toApiError(err);
      expect(isApiError(result)).toBe(true);
      expect(result.code).toBe("internal_error");
      expect(result.message).toBe("something broke");
    });

    it("converts string to ApiError", () => {
      const result = toApiError("error message");
      expect(isApiError(result)).toBe(true);
      expect(result.code).toBe("internal_error");
      expect(result.message).toBe("error message");
    });

    it("converts unknown type to ApiError", () => {
      const result = toApiError(42);
      expect(isApiError(result)).toBe(true);
      expect(result.code).toBe("internal_error");
      expect(result.message).toBe("42");
    });
  });

  describe("logApiError (Phase 2.5)", () => {
    it("logs only code, endpoint and status — never details or bodies", () => {
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        const err = new ApiError("invalid_credentials", "password=SuperSecret123 leaked?", {
          httpStatus: 401,
          details: { password: "SuperSecret123" },
        });
        logApiError("/api/auth/login", err);

        expect(spy).toHaveBeenCalledTimes(1);
        const logged = spy.mock.calls[0]!.join(" ");
        expect(logged).toContain("invalid_credentials");
        expect(logged).toContain("/api/auth/login");
        expect(logged).toContain("401");
        // Neither the message nor the details may reach the console.
        expect(logged).not.toContain("SuperSecret123");
      } finally {
        spy.mockRestore();
      }
    });

    it('renders "-" when httpStatus is unknown', () => {
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        logApiError("/api/trace", new ApiError("server_unreachable", "net down"));
        const logged = spy.mock.calls[0]!.join(" ");
        expect(logged).toContain("status=-");
      } finally {
        spy.mockRestore();
      }
    });
  });
});
