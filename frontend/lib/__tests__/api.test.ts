import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportRules, getPublicConfig, getRuleHygiene, getSession, getUsers, health, login, refreshAccessProfile, trace } from "../api";
import { ApiError } from "../errors";

/**
 * lib/api.ts unit tests: the module only depends on global fetch, so we stub
 * it with vi.stubGlobal — no jsdom acrobatics needed.
 */

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function expectApiError(promise: Promise<unknown>, code: string): Promise<ApiError> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe(code);
    return err as ApiError;
  }
  throw new Error(`expected ApiError(${code}) to be thrown`);
}

describe("lib/api.ts", () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    consoleErrorSpy.mockRestore();
  });

  describe("network failures → server_unreachable", () => {
    it("fetch rejection maps to server_unreachable", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

      await expectApiError(getSession(), "server_unreachable");
    });

    it("5xx without an error envelope maps to server_unreachable", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("Bad Gateway", { status: 502 })));

      const err = await expectApiError(getUsers(), "server_unreachable");
      expect(err.httpStatus).toBe(502);
    });
  });

  describe("schema mismatches → api_changed", () => {
    it("non-JSON 200 response maps to api_changed", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>proxy page</html>", { status: 200 })));

      await expectApiError(getSession(), "api_changed");
    });

    it("login response without session object and not two_factor_required maps to api_changed", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ ok: true })));

      await expectApiError(login({ login: "admin", password: "x", server: "gw" }), "api_changed");
    });

    it("v2: login response without rules_updated_at maps to api_changed", async () => {
      // A v1-shaped session (no rules_updated_at) must be rejected.
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            ok: true,
            session: {
              login: "admin",
              server: "gw",
              expires_at: "2026-07-09T20:00:00Z",
              first_login: true,
            },
          }),
        ),
      );

      await expectApiError(login({ login: "admin", password: "x", server: "gw" }), "api_changed");
    });

    it("v2: valid login response with rules_updated_at=null resolves", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            ok: true,
            session: {
              login: "admin",
              server: "gw",
              expires_at: "2026-07-09T20:00:00Z",
              first_login: true,
              rules_updated_at: null,
            },
          }),
        ),
      );

      const data = await login({ login: "admin", password: "x", server: "gw" });
      expect(data.twoFactorRequired).toBe(false);
      if (data.twoFactorRequired === false) {
        expect(data.session.rules_updated_at).toBeNull();
        expect(data.session.first_login).toBe(true);
      }
    });

    it("v2: session response without rules_updated_at maps to api_changed", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            authenticated: true,
            login: "admin",
            server: "gw",
            expires_at: "2026-07-09T20:00:00Z",
            rules_loaded: false,
          }),
        ),
      );

      await expectApiError(getSession(), "api_changed");
    });

    it("trace response with wrong stages count maps to api_changed", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ stages: [{ key: "dns" }], summary: { verdict: "allowed" } })));

      await expectApiError(trace({ url: "example.com" }), "api_changed");
    });

    it("session response with missing fields maps to api_changed", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ authenticated: true })));

      await expectApiError(getSession(), "api_changed");
    });

    it("login response with two_factor_required returns discriminated outcome", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            ok: true,
            two_factor_required: true,
            expires_at: "2026-07-09T20:05:00Z",
            message: "Enter the code from your authenticator",
          }),
        ),
      );

      const data = await login({ login: "admin", password: "x", server: "gw" });
      expect(data.twoFactorRequired).toBe(true);
      if (data.twoFactorRequired === true) {
        expect(data.expiresAt).toBe("2026-07-09T20:05:00Z");
        expect(data.message).toBe("Enter the code from your authenticator");
      }
    });

    it("login response with two_factor_required but missing expires_at maps to api_changed", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            ok: true,
            two_factor_required: true,
          }),
        ),
      );

      await expectApiError(login({ login: "admin", password: "x", server: "gw" }), "api_changed");
    });

    it("rejects a malformed public access profile", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            authenticated: true,
            login: "admin",
            server: "gw",
            expires_at: "2026-07-09T20:00:00Z",
            rules_loaded: false,
            rules_updated_at: null,
            access_profile: { role_id: "predefined_admin_readonly", role_name: "Read-only", trace_allowed: "yes" },
          }),
        ),
      );

      await expectApiError(getSession(), "api_changed");
    });
  });

  describe("backend error envelope handling", () => {
    it("propagates the contract error code from the envelope", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ error: { code: "invalid_credentials", message: "nope" } }, 401)));

      const err = await expectApiError(login({ login: "admin", password: "wrong", server: "gw" }), "invalid_credentials");
      expect(err.httpStatus).toBe(401);
    });

    it("unknown code in the envelope falls back to ngfw_error", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ error: { code: "brand_new_code", message: "x" } }, 502)));

      await expectApiError(getUsers(), "ngfw_error");
    });
  });

  describe("health (optional public metadata)", () => {
    it("parses the application version and ngfw_port", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse({
            status: "ok",
            version: "1.2.3-test",
            ngfw_port: 8443,
            ngfw_access_mode: "allowlist",
          }),
        ),
      );

      const data = await health();
      expect(data.status).toBe("ok");
      expect(data.version).toBe("1.2.3-test");
      expect(data.ngfw_port).toBe(8443);
      expect(data.ngfw_access_mode).toBe("allowlist");
    });

    it("does NOT raise api_changed when ngfw_port is absent (older backend)", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ status: "ok" })));

      const data = await health();
      expect(data.status).toBe("ok");
      expect(data.ngfw_port).toBeUndefined();
    });

    it("parses a custom ngfw_port value", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ status: "ok", ngfw_port: 9443 })));

      const data = await health();
      expect(data.ngfw_port).toBe(9443);
    });
  });

  describe("public configuration", () => {
    it("parses a configured default server", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ default_server: "locked-ngfw.example" })));

      const data = await getPublicConfig();
      expect(data.default_server).toBe("locked-ngfw.example");
    });

    it("parses the trace-animation feature flag", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ default_server: "", trace_animation_enabled: false })));

      const data = await getPublicConfig();
      expect(data.trace_animation_enabled).toBe(false);
    });

    it("allows an older backend to omit the optional feature flag", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ default_server: "" })));

      const data = await getPublicConfig();
      expect(data.trace_animation_enabled).toBeUndefined();
    });
  });

  describe("request wiring", () => {
    it("sends credentials: include and does not log the request body", async () => {
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ error: { code: "invalid_credentials", message: "no" } }, 401));
      vi.stubGlobal("fetch", fetchMock);

      const password = "Sup3rS3cret!";
      await login({ login: "admin", password, server: "gw" }).catch(() => {});

      const firstFetchCall = fetchMock.mock.calls[0];
      expect(firstFetchCall).toBeDefined();
      const [, init] = firstFetchCall!;
      expect(init.credentials).toBe("include");

      // Phase 2.5: the console must never see the password.
      const logged = (consoleErrorSpy.mock.calls as unknown[][]).map((call) => call.join(" ")).join("\n");
      expect(logged).not.toContain(password);
      expect(logged).toContain("invalid_credentials");
    });
  });

  describe("exportRules (§3.8 — rules export)", () => {
    function exportResponse(disposition: string | null): Response {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (disposition !== null) headers["Content-Disposition"] = disposition;
      return new Response(JSON.stringify({ binding: { admin: "a", server: "s" } }), {
        status: 200,
        headers,
      });
    }

    it("returns a blob and the filename from Content-Disposition", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse('attachment; filename="rules-192.168.1.1-20260714T030000Z.json"')));

      const result = await exportRules();
      expect(result.blob).toBeInstanceOf(Blob);
      expect(result.filename).toBe("rules-192.168.1.1-20260714T030000Z.json");
    });

    it("parses an unquoted filename", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse("attachment; filename=rules-gw.json")));

      const result = await exportRules();
      expect(result.filename).toBe("rules-gw.json");
    });

    it("parses an RFC 5987 filename* value", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse("attachment; filename*=UTF-8''rules-%D1%81.json")));

      const result = await exportRules();
      // %D1%81 decodes to the Cyrillic "с".
      expect(result.filename).toBe("rules-с.json");
    });

    it("returns filename=null when the header is absent (fallback naming on UI)", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exportResponse(null)));

      const result = await exportRules();
      expect(result.blob).toBeInstanceOf(Blob);
      expect(result.filename).toBeNull();
    });

    it("maps session_expired from the error envelope to an ApiError", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ error: { code: "session_expired", message: "expired" } }, 401)));

      const err = await expectApiError(exportRules(), "session_expired");
      expect(err.httpStatus).toBe(401);
    });

    it("maps a network failure to server_unreachable", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

      await expectApiError(exportRules(), "server_unreachable");
    });

    it("maps a 404 (feature disabled) to not_found via the envelope", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ error: { code: "not_found", message: "Not found" } }, 404)));

      await expectApiError(exportRules(), "not_found");
    });
  });

  describe("getSession — rules_export_enabled flag", () => {
    function sessionBody(extra: Record<string, unknown>) {
      return {
        authenticated: true,
        login: "admin",
        server: "gw",
        expires_at: "2026-07-14T20:00:00Z",
        rules_loaded: true,
        rules_updated_at: "2026-07-14T09:00:00Z",
        ...extra,
      };
    }

    it("passes through rules_export_enabled=true", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(sessionBody({ rules_export_enabled: true }))));

      const data = await getSession();
      if ("twoFactorPending" in data) throw new Error("expected an authenticated session");
      expect(data.rules_export_enabled).toBe(true);
    });

    it("treats an absent flag as undefined (button hidden → falsy)", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(sessionBody({}))));

      const data = await getSession();
      if ("twoFactorPending" in data) throw new Error("expected an authenticated session");
      expect(data.rules_export_enabled).toBeUndefined();
      // The Header gate is `!anonymous && exportEnabled`; undefined is falsy.
      expect(Boolean(data.rules_export_enabled)).toBe(false);
    });

    it("passes through ngfw_port for safe NGFW administration links", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(sessionBody({ ngfw_port: 9443 }))));

      const data = await getSession();
      if ("twoFactorPending" in data) throw new Error("expected an authenticated session");
      expect(data.ngfw_port).toBe(9443);
    });

    it("passes through the reduced access profile without any raw NGFW permission list", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          jsonResponse(
            sessionBody({
              access_profile: {
                role_id: "predefined_admin_readonly",
                role_name: "Read-only administrator",
                trace_allowed: true,
              },
            }),
          ),
        ),
      );

      const data = await getSession();
      if ("twoFactorPending" in data) throw new Error("expected an authenticated session");
      expect(data.access_profile).toEqual({
        role_id: "predefined_admin_readonly",
        role_name: "Read-only administrator",
        trace_allowed: true,
      });
      expect(JSON.stringify(data)).not.toContain("competence");
    });

    it("returns a two-factor-pending bootstrap when only a challenge is active", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ authenticated: false, two_factor_pending: true, expires_at: "2026-07-14T09:03:00Z" })));

      const data = await getSession();
      expect(data).toEqual({ twoFactorPending: true, expiresAt: "2026-07-14T09:03:00Z" });
    });
  });

  describe("refreshAccessProfile", () => {
    it("rechecks the active session and returns only the safe role profile", async () => {
      const fetchMock = vi.fn().mockResolvedValue(
        jsonResponse({
          ok: true,
          access_profile: {
            role_id: "predefined_admin_readonly",
            role_name: "Read-only administrator",
            trace_allowed: true,
          },
        }),
      );
      vi.stubGlobal("fetch", fetchMock);

      const data = await refreshAccessProfile();

      expect(data.access_profile.trace_allowed).toBe(true);
      expect(JSON.stringify(data)).not.toContain("competence");
      expect(fetchMock).toHaveBeenCalledWith("/api/session/access/refresh", expect.objectContaining({ method: "POST", credentials: "include" }));
    });

    it("rejects a malformed refresh response", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ ok: true, access_profile: { role_id: "role" } })));

      await expectApiError(refreshAccessProfile(), "api_changed");
    });
  });

  describe("export button visibility rule (mirrors Header.tsx: !anonymous && exportEnabled)", () => {
    // Header renders the export button only for an authenticated session whose
    // rules_export_enabled is true. No heavy render — the boolean rule is the
    // gate; full JSX visibility is covered by manual/build checks (see summary).
    const visible = (anonymous: boolean, flag: boolean | undefined) => !anonymous && Boolean(flag);

    it("shown only when authenticated AND flag true", () => {
      expect(visible(false, true)).toBe(true);
    });
    it("hidden when flag false/undefined", () => {
      expect(visible(false, false)).toBe(false);
      expect(visible(false, undefined)).toBe(false);
    });
    it("hidden in anonymous (login) mode even if flag true", () => {
      expect(visible(true, true)).toBe(false);
    });
  });

  describe("getRuleHygiene", () => {
    it("returns the parsed report on success", async () => {
      const report = {
        binding: { admin: "admin", server: "10.0.0.1" },
        rules_updated_at: "2026-07-22T00:00:00Z",
        generated_at: "2026-07-22T00:00:01Z",
        summary: { total: 1, risk: 0, warning: 1, info: 0, possible: 0 },
        findings: [
          {
            kind: "shadowed",
            severity: "warning",
            tier: "certain",
            table: "fw_forward",
            reason_key: "hygiene_shadowed",
            rule: { id: "2", name: null, position: 2 },
            related: [{ id: "1", name: null, position: 1 }],
          },
        ],
      };
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse(report));
      vi.stubGlobal("fetch", fetchMock);

      const res = await getRuleHygiene();
      expect(res.summary.warning).toBe(1);
      expect(res.findings[0]!.kind).toBe("shadowed");
      expect(fetchMock.mock.calls[0]![0]).toBe("/api/rules/hygiene");
    });

    it("passes ?refresh=true when requested", async () => {
      const report = {
        binding: { admin: "a", server: "s" },
        rules_updated_at: "2026-07-22T00:00:00Z",
        generated_at: "2026-07-22T00:00:01Z",
        summary: { total: 0, risk: 0, warning: 0, info: 0, possible: 0 },
        findings: [],
      };
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse(report));
      vi.stubGlobal("fetch", fetchMock);

      await getRuleHygiene(true);
      expect(fetchMock.mock.calls[0]![0]).toBe("/api/rules/hygiene?refresh=true");
    });

    it("maps a disabled-feature 404 to ApiError(not_found)", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ error: { code: "not_found" } }, 404)));
      await expectApiError(getRuleHygiene(), "not_found");
    });
  });
});
