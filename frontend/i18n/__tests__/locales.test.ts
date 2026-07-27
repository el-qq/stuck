import { describe, it, expect } from "vitest";
import { en, type MessageKey } from "../en";
import { CORE_MESSAGE_KEYS } from "../core";
import { DICTIONARIES, SUPPORTED_LOCALES, LOCALE_REGION_ORDER, matchLocale, resolveLocale, type Locale } from "../locales";

/**
 * The suite is driven by the registry, never by a hand-maintained list of
 * imports: a locale that is registered but forgotten here used to pass by
 * being absent. Everything below iterates `SUPPORTED_LOCALES`.
 */
const localeCodes = SUPPORTED_LOCALES.map((entry) => entry.code);
const fullLocales = SUPPORTED_LOCALES.filter((entry) => entry.tier === "full").map((entry) => entry.code);
const coreLocales = SUPPORTED_LOCALES.filter((entry) => entry.tier === "core").map((entry) => entry.code);

const enKeys = Object.keys(en) as MessageKey[];
const coreKeySet = new Set<string>(CORE_MESSAGE_KEYS);

function entries(locale: Locale): [string, string | undefined][] {
  return Object.entries(DICTIONARIES[locale]);
}

function value(locale: Locale, key: string): string | undefined {
  return (DICTIONARIES[locale] as Record<string, string | undefined>)[key];
}

/**
 * A key is mandatory for a full locale always, and for a core locale only when
 * it is part of the core set — that is exactly what the two tiers mean. Keys a
 * core locale omits render in English at runtime.
 */
function expectKeysPresent(keys: readonly string[]) {
  for (const locale of localeCodes) {
    const tier = SUPPORTED_LOCALES.find((entry) => entry.code === locale)!.tier;
    for (const key of keys) {
      if (tier === "core" && !coreKeySet.has(key)) continue;
      const translated = value(locale, key);
      expect(translated, `Locale ${locale} is missing: ${key}`).toBeDefined();
      expect(typeof translated === "string" && translated.trim().length > 0, `Locale ${locale} has an empty value for: ${key}`).toBe(true);
    }
  }
}

describe("locale registry", () => {
  it("registry and dictionaries describe the same locales", () => {
    expect(new Set(Object.keys(DICTIONARIES))).toEqual(new Set(localeCodes));
  });

  it("locale codes are unique", () => {
    expect(new Set(localeCodes).size).toBe(localeCodes.length);
  });

  it("every locale is filed under a known market region", () => {
    for (const entry of SUPPORTED_LOCALES) {
      expect(LOCALE_REGION_ORDER, `Locale ${entry.code}`).toContain(entry.region);
    }
  });

  it("English is complete and is the fallback source", () => {
    expect(fullLocales).toContain("en");
    expect(enKeys.length).toBeGreaterThan(0);
  });

  it("every core key exists in the canonical dictionary", () => {
    for (const key of CORE_MESSAGE_KEYS) {
      expect(en[key], `Core key missing from en.ts: ${key}`).toBeDefined();
    }
  });
});

describe("translation tiers (FR-6.2)", () => {
  it("full locales translate every key", () => {
    for (const locale of fullLocales) {
      const keys = new Set(Object.keys(DICTIONARIES[locale]));
      const missing = enKeys.filter((key) => !keys.has(key));
      expect(missing, `Full locale ${locale} is missing keys`).toEqual([]);
    }
  });

  it("core locales translate at least the core key set", () => {
    for (const locale of coreLocales) {
      const keys = new Set(Object.keys(DICTIONARIES[locale]));
      const missing = CORE_MESSAGE_KEYS.filter((key) => !keys.has(key));
      expect(missing, `Core locale ${locale} is missing core keys`).toEqual([]);
    }
  });

  it("no locale defines a key that does not exist in English", () => {
    const known = new Set<string>(enKeys);
    for (const locale of localeCodes) {
      const extra = Object.keys(DICTIONARIES[locale]).filter((key) => !known.has(key));
      expect(extra, `Locale ${locale} has unknown keys`).toEqual([]);
    }
  });

  it("no empty or whitespace-only translations", () => {
    for (const locale of localeCodes) {
      const blank = entries(locale).filter(([, text]) => typeof text === "string" && text.trim() === "");
      expect(blank, `Locale ${locale} has blank values`).toEqual([]);
    }
  });

  it("placeholders match English wherever a key is translated", () => {
    const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
    for (const locale of localeCodes) {
      if (locale === "en") continue;
      for (const [key, text] of entries(locale)) {
        const source = en[key as MessageKey];
        if (source === undefined || text === undefined) continue;
        expect(placeholders(text), `Locale ${locale}, key ${key}`).toEqual(placeholders(source));
      }
    }
  });
});

describe("terminology policy (see en.ts)", () => {
  it("the product name is never translated", () => {
    for (const locale of localeCodes) {
      expect(value(locale, "common.appName"), `Locale ${locale}`).toBe("STUCK");
    }
  });

  it("NGFW acronyms stay literal", () => {
    for (const locale of localeCodes) {
      for (const key of ["stage.dns", "stage.dnat", "stage.snat"] as const) {
        const translated = value(locale, key);
        if (translated === undefined) continue;
        expect(translated, `Locale ${locale} translated the acronym in ${key}`).toBe(en[key]);
      }
    }
  });

  it("the tagline keeps the NGFW product name", () => {
    for (const locale of localeCodes) {
      const tagline = value(locale, "common.appTagline");
      if (tagline === undefined) continue;
      expect(tagline, `Locale ${locale}`).toContain("NGFW");
    }
  });
});

describe("language tag matching", () => {
  it("matches an exact tag, case- and separator-insensitively", () => {
    expect(matchLocale("pt-BR")).toBe("pt-BR");
    expect(matchLocale("PT-br")).toBe("pt-BR");
    expect(matchLocale("pt_BR")).toBe("pt-BR");
    expect(matchLocale("en")).toBe("en");
  });

  it("falls back to the base language for an unlisted region", () => {
    // The old two-character slice could only do this half, which is why a
    // regional dictionary was unreachable.
    expect(matchLocale("pt")).toBe("pt-BR");
    expect(matchLocale("pt-PT")).toBe("pt-BR");
    expect(matchLocale("es-MX")).toBe("es");
    expect(matchLocale("es-ES")).toBe("es");
    expect(matchLocale("en-US")).toBe("en");
    expect(matchLocale("uz-Latn-UZ")).toBe("uz");
  });

  it("returns null for an unsupported or empty tag", () => {
    expect(matchLocale("zh-CN")).toBeNull();
    expect(matchLocale("")).toBeNull();
    expect(matchLocale("   ")).toBeNull();
  });

  it("resolves the first supported browser candidate", () => {
    expect(resolveLocale(["zh-CN", "ja", "vi-VN", "en"])).toBe("vi");
    expect(resolveLocale([null, undefined, "tr-TR"])).toBe("tr");
    expect(resolveLocale(["zh-CN"])).toBeNull();
  });
});

describe("error message coverage (docs/API_CONTRACT.md)", () => {
  // Every contract code is part of the core set, so this holds for every
  // locale at either tier.
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
    // Rule snapshots and diff (docs/source/snapshots.md, fork f).
    "snapshot_limit_reached",
    "snapshot_import_invalid",
    "snapshot_import_unsupported_format",
    "snapshot_import_too_large",
    // Access compare (docs/source/comparison.md, §3.i).
    "compare_side_invalid",
  ];

  it("every contract error code is a core key", () => {
    for (const code of requiredErrorCodes) {
      expect(coreKeySet.has(`errors.${code}`), `errors.${code} must be in CORE_MESSAGE_KEYS`).toBe(true);
    }
  });

  it("every contract error code is translated in every locale", () => {
    expectKeysPresent(requiredErrorCodes.map((code) => `errors.${code}`));
  });
});

describe("pipeline stage names", () => {
  const stageNames = ["pre_filter", "rate_limit", "dns", "dnat", "content_filter", "antivirus", "firewall", "app_control", "ips", "snat", "destination"];

  it("all stage names are present in every locale", () => {
    expectKeysPresent(stageNames.map((stage) => `stage.${stage}`));
  });
});

describe("Iteration 2 keys (contract v2.1)", () => {
  // New/changed UI strings: read-only admin hint (customer req #5),
  // session-expired relogin notice (v2.1 §1.2), no-port server format hint.
  it("all v2 keys are present and non-empty", () => {
    expectKeysPresent(["login.readonlyHint", "login.unrestrictedNgfwWarning", "login.sessionExpiredNotice", "login.validation.serverFormat"]);
  });

  it("server hints no longer instruct entering a port", () => {
    // v2: server is entered WITHOUT a port.
    expect(en["login.validation.serverFormat"]).not.toMatch(/host:port|ip:port/i);
    expect(en["login.serverPlaceholder"]).not.toMatch(/:\d+/);
  });
});

describe("Iteration 3 keys (FR-10, contract v2.2)", () => {
  it("show/hide password keys present and non-empty (FR-10.2)", () => {
    expectKeysPresent(["login.showPassword", "login.hidePassword"]);
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
    expect(DICTIONARIES.ru["header.refresh"]).toBe("Обновить");
  });

  it("check-address placeholder demonstrates an explicit port (FR-10.10)", () => {
    for (const locale of localeCodes) {
      expect(value(locale, "check.addressPlaceholder"), `Locale ${locale} placeholder`).toContain("example.com:12345");
    }
  });

  it("login screen no longer suggests a gateway default (FR-10.1)", () => {
    for (const locale of localeCodes) {
      const label = value(locale, "login.serverLabel");
      if (label === undefined) continue;
      expect(/gateway|шлюз/i.test(label), `Locale ${locale} server label still mentions the gateway default: "${label}"`).toBe(false);
    }
  });
});

describe("Iteration 4 keys (FR-11 — demo mode)", () => {
  it("all demo keys present and non-empty (FR-11.6)", () => {
    expectKeysPresent([
      "common.or",
      "demo.button",
      "demo.bannerTitle",
      "demo.bannerText",
      "demo.exit",
      "demo.categoryVideo", // iteration 5: no longer used in code, but kept in dictionaries
      "demo.targetsLabel", // iteration 5: selectable demo targets label
    ]);
  });
});

describe("Iteration 7 keys (FR-12 — rules export)", () => {
  it("export keys present and non-empty", () => {
    expectKeysPresent(["header.exportRules", "header.exporting", "rulesExport.title", "rulesExport.message", "rulesExport.download"]);
  });
});

describe("Rule snapshots and diff keys (docs/source/snapshots.md, fork f)", () => {
  const snapshotKeys = [
    "snapshots.title",
    "snapshots.subtitle",
    "snapshots.compareTitle",
    "snapshots.compareA",
    "snapshots.compareB",
    "snapshots.current",
    "snapshots.listTitle",
    "snapshots.limitCounter",
    "snapshots.namePlaceholder",
    "snapshots.create",
    "snapshots.creating",
    "snapshots.import",
    "snapshots.importing",
    "snapshots.empty",
    "snapshots.sourceImported",
    "snapshots.sourceManual",
    "snapshots.foreignBadge",
    "snapshots.rowCounts",
    "snapshots.delete",
    "snapshots.deleteConfirmTitle",
    "snapshots.deleteConfirmMessage",
    "snapshots.diffLoading",
    "snapshots.diffClean",
    "snapshots.anonymizedBanner",
    "snapshots.foreignServerBanner",
    "snapshots.statesTitle",
    "snapshots.countAdded",
    "snapshots.countRemoved",
    "snapshots.countChanged",
    "snapshots.countMoved",
    "snapshots.kindAdded",
    "snapshots.kindRemoved",
    "snapshots.kindChanged",
    "snapshots.kindMoved",
    "snapshots.positionAdded",
    "snapshots.positionRemoved",
    "snapshots.positionBoth",
    "snapshots.tableFwPreFilter",
    "snapshots.tableFwForward",
    "snapshots.tableFwInput",
    "snapshots.tableFwDnat",
    "snapshots.tableFwSnat",
    "snapshots.tableHwMac",
    "snapshots.tableHwSrcIp",
    "snapshots.tableHwDstIp",
    "snapshots.tableHwSrcDstIp",
    "snapshots.tableCfRules",
    "snapshots.tableShaperRules",
    "snapshots.tableIpsBypass",
    "snapshots.tableAliases",
    "snapshots.tableUsers",
    "snapshots.state.fw_state",
    "snapshots.state.cf_state",
    "snapshots.state.ips_state",
    "snapshots.state.av_enabled",
    "snapshots.state.shaper_state",
    "snapshots.state.hw_settings_mode",
    "snapshots.state.fw_settings_automatic_snat_enabled",
  ];

  it("all snapshot/diff keys are present and non-empty", () => {
    expectKeysPresent(snapshotKeys);
  });
});

describe("Access compare keys (docs/source/comparison.md)", () => {
  const compareKeys = [
    "compare.title",
    "compare.subtitle",
    "compare.sideA",
    "compare.sideB",
    "compare.protocolLabel",
    "compare.modeNone",
    "compare.modeUser",
    "compare.modeIp",
    "compare.manualIpLabel",
    "compare.manualIpPlaceholder",
    "compare.submit",
    "compare.comparing",
    "compare.resultLoading",
    "compare.empty",
    "compare.noSubject",
    "compare.identicalSubjectsBanner",
    "compare.noStageDifferencesBanner",
    "compare.contextMismatchBanner",
    "compare.contextIncompleteBanner",
    "compare.primaryDivergenceBanner",
    "compare.differentRuleTag",
    "compare.primaryTag",
    "compare.classificationSame",
    "compare.classificationDivergent",
    "compare.classificationIncomparable",
    "compare.legendHint",
    "compare.reason.unknown_user",
    "compare.reason.multiple_source_ips",
    "compare.reason.source_ip_not_assigned",
    "compare.reason.invalid_source_ip",
  ];

  it("all access-compare keys are present and non-empty", () => {
    expectKeysPresent(compareKeys);
  });
});

describe("Protocol selector keys (NGFW firewall protocol filter)", () => {
  // The 8-way protocol picker (check + access-compare forms) only localizes
  // the "any" wildcard label — acronyms and "TCP/UDP" are literal. The two
  // reason keys are emitted for an undetermined-protocol outcome:
  // `fw_protocol_unknown` by the firewall/DNAT/SNAT stages (they reuse the
  // firewall condition reason keys) and `pre_filter_protocol_unknown` by
  // the preliminary-filter stage.
  it("all protocol keys are present and non-empty", () => {
    expectKeysPresent(["protocol.any", "reason.fw_protocol_unknown", "reason.pre_filter_protocol_unknown"]);
  });
});
