import { StageKey } from "./types";

// Console routes: #/firewall/firewall-users (forward/input), #/firewall/dnat,
// #/firewall/prefiltering, #/firewall/hardware-filtering (no STUCK stage yet).
const SECTION_BY_STAGE: Partial<Record<StageKey, string>> = {
  pre_filter: "firewall/prefiltering",
  dnat: "firewall/dnat",
  content_filter: "settings/access-rules/content-filter",
  firewall: "firewall/firewall-users",
  ips: "settings/access-rules/ips",
  snat: "firewall/snat",
};

/**
 * Builds a link to the relevant NGFW administration section. The console
 * itself owns rule selection, so STUCK deliberately does not invent an
 * undocumented per-rule URL format.
 */
export function ngfwRuleSectionUrl(server: string | undefined, port: number | undefined, stage: StageKey, ruleId: string | undefined): string | null {
  if (!server || !ruleId?.trim() || typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  const section = SECTION_BY_STAGE[stage];
  if (!section) return null;

  try {
    const url = new URL(`https://${server}:${port}`);
    url.hash = `/${section}`;
    return url.toString();
  } catch {
    return null;
  }
}
