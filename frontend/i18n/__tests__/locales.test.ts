import { describe, it, expect } from "vitest";
import { en } from "../en";
import { es } from "../es";
import { ru } from "../ru";
import { kk } from "../kk";
import { ms } from "../ms";
import { fr } from "../fr";
import { be } from "../be";
import { ky } from "../ky";
import { hy } from "../hy";

describe("i18n locales (FR-6: Localization)", () => {
  const locales = {
    en,
    es,
    ru,
    kk,
    ms,
    fr,
    be,
    ky,
    hy,
  };

  const localeNames = Object.keys(locales) as Array<keyof typeof locales>;

  describe("Key consistency (FR-6.2)", () => {
    it("all locales have the same set of keys", () => {
      const enKeys = new Set(Object.keys(en));
      const allKeysMatch = localeNames.every((locale) => {
        const localeKeys = new Set(Object.keys(locales[locale]));
        if (localeKeys.size !== enKeys.size) return false;
        return [...enKeys].every((key) => localeKeys.has(key));
      });
      expect(allKeysMatch).toBe(true);
    });

    it("no extra keys in non-English locales", () => {
      const enKeys = new Set(Object.keys(en));
      const otherLocales = localeNames.filter((l) => l !== "en");
      for (const locale of otherLocales) {
        const localeKeys = Object.keys(locales[locale]);
        const extraKeys = localeKeys.filter((key) => !enKeys.has(key));
        expect(extraKeys).toHaveLength(0);
      }
    });

    it("no missing keys in non-English locales", () => {
      const enKeys = Object.keys(en);
      const otherLocales = localeNames.filter((l) => l !== "en");
      for (const locale of otherLocales) {
        const localeKeys = new Set(Object.keys(locales[locale]));
        const missingKeys = enKeys.filter((key) => !localeKeys.has(key));
        expect(missingKeys).toHaveLength(0);
      }
    });
  });

  describe("Empty strings (FR-6.2)", () => {
    it("no empty translation strings in any locale", () => {
      for (const locale of localeNames) {
        const entries = Object.entries(locales[locale]);
        const emptyEntries = entries.filter(([, value]) => value === "");
        expect(emptyEntries).toHaveLength(0);
      }
    });

    it("no whitespace-only translation strings", () => {
      for (const locale of localeNames) {
        const entries = Object.entries(locales[locale]);
        const whitespaceEntries = entries.filter(([, value]) => typeof value === "string" && value.trim() === "");
        expect(whitespaceEntries).toHaveLength(0);
      }
    });
  });

  describe("Error message coverage (API_CONTRACT.md)", () => {
    const requiredErrorCodes = [
      "validation_error",
      "invalid_server_address",
      "ngfw_host_not_allowed",
      "invalid_credentials",
      "second_factor_required",
      "second_factor_invalid",
      "second_factor_expired",
      "insufficient_ngfw_permissions",
      "readonly_admin_required",
      "not_authenticated",
      "session_expired",
      "server_unreachable",
      "api_changed",
      "ngfw_error",
      "not_found",
      "internal_error",
    ];

    it("all error codes are present in en locale", () => {
      for (const code of requiredErrorCodes) {
        const key = `errors.${code}`;
        expect(en[key as keyof typeof en]).toBeDefined();
        expect(en[key as keyof typeof en]).not.toBe("");
      }
    });

    it("all error codes are present in all locales", () => {
      for (const locale of localeNames) {
        for (const code of requiredErrorCodes) {
          const key = `errors.${code}`;
          expect(locales[locale][key as keyof typeof en]).toBeDefined();
        }
      }
    });
  });

  describe("Stage names coverage", () => {
    const stageNames = ["pre_filter", "rate_limit", "dns", "dnat", "content_filter", "antivirus", "firewall", "app_control", "ips", "snat", "destination"];

    it("all stage names are present in en locale", () => {
      for (const stage of stageNames) {
        const key = `stage.${stage}`;
        expect(en[key as keyof typeof en]).toBeDefined();
      }
    });

    it("all stage names are present in all locales", () => {
      for (const locale of localeNames) {
        for (const stage of stageNames) {
          const key = `stage.${stage}`;
          expect(locales[locale][key as keyof typeof en]).toBeDefined();
        }
      }
    });
  });

  describe("Iteration 2 keys (contract v2.1)", () => {
    // New/changed UI strings: read-only admin hint (customer req #5),
    // session-expired relogin notice (v2.1 §1.2), no-port server format hint.
    const v2Keys = ["login.readonlyHint", "login.unrestrictedNgfwWarning", "login.sessionExpiredNotice", "login.validation.serverFormat"];

    it("all v2 keys are present and non-empty in every locale", () => {
      for (const locale of localeNames) {
        for (const key of v2Keys) {
          const value = locales[locale][key as keyof typeof en];
          expect(value, `Locale ${locale} is missing: ${key}`).toBeDefined();
          expect(typeof value === "string" && value.trim().length > 0, `Locale ${locale} has an empty value for: ${key}`).toBe(true);
        }
      }
    });

    it("server hints no longer instruct entering a port", () => {
      // v2: server is entered WITHOUT a port.
      expect(en["login.validation.serverFormat"]).not.toMatch(/host:port|ip:port/i);
      expect(en["login.serverPlaceholder"]).not.toMatch(/:\d+/);
    });
  });

  describe("Iteration 3 keys (FR-10, contract v2.2)", () => {
    it("show/hide password keys present and non-empty in every locale (FR-10.2)", () => {
      for (const locale of localeNames) {
        for (const key of ["login.showPassword", "login.hidePassword"]) {
          const value = locales[locale][key as keyof typeof en];
          expect(value, `Locale ${locale} is missing: ${key}`).toBeDefined();
          expect(typeof value === "string" && value.trim().length > 0, `Locale ${locale} has an empty value for: ${key}`).toBe(true);
        }
      }
    });

    it("removed keys are gone from the dictionary (FR-10.3, FR-10.6)", () => {
      // login.serverHint (the "(default: gateway)" hint) and verdict.replay
      // ("Replay animation") were removed in iteration 3.
      const keys = Object.keys(en);
      expect(keys).not.toContain("login.serverHint");
      expect(keys).not.toContain("verdict.replay");
    });

    it('refresh button is renamed to a plain "Refresh" (FR-10.8)', () => {
      // No locale should mention "rules" in the refresh button label anymore.
      expect(en["header.refresh"]).toBe("Refresh");
      expect(ru["header.refresh"]).toBe("Обновить");
    });

    it("check-address placeholder demonstrates an explicit port (FR-10.10)", () => {
      for (const locale of localeNames) {
        const value = locales[locale]["check.addressPlaceholder" as keyof typeof en];
        expect(value, `Locale ${locale} placeholder`).toContain("example.com:12345");
      }
    });

    it("login screen no longer suggests a gateway default (FR-10.1)", () => {
      for (const locale of localeNames) {
        const label = locales[locale]["login.serverLabel" as keyof typeof en];
        expect(/gateway|шлюз/i.test(label), `Locale ${locale} server label still mentions the gateway default: "${label}"`).toBe(false);
      }
    });
  });

  describe("Iteration 4 keys (FR-11 — demo mode)", () => {
    const demoKeys = [
      "common.or",
      "demo.button",
      "demo.bannerTitle",
      "demo.bannerText",
      "demo.exit",
      "demo.categoryVideo", // iteration 5: no longer used in code, but kept in dictionaries
      "demo.targetsLabel", // iteration 5: selectable demo targets label
    ];

    it("all demo keys present and non-empty in every locale (FR-11.6)", () => {
      for (const locale of localeNames) {
        for (const key of demoKeys) {
          const value = locales[locale][key as keyof typeof en];
          expect(value, `Locale ${locale} is missing: ${key}`).toBeDefined();
          expect(typeof value === "string" && value.trim().length > 0, `Locale ${locale} has an empty value for: ${key}`).toBe(true);
        }
      }
    });
  });

  describe("Iteration 7 keys (FR-12 — rules export)", () => {
    const exportKeys = ["header.exportRules", "header.exporting", "rulesExport.title", "rulesExport.message", "rulesExport.download"];

    it("export keys present and non-empty in every locale", () => {
      for (const locale of localeNames) {
        for (const key of exportKeys) {
          const value = locales[locale][key as keyof typeof en];
          expect(value, `Locale ${locale} is missing: ${key}`).toBeDefined();
          expect(typeof value === "string" && value.trim().length > 0, `Locale ${locale} has an empty value for: ${key}`).toBe(true);
        }
      }
    });
  });
});
