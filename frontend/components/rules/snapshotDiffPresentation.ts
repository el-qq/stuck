import type { MessageKey } from "@/i18n/en";
import { ngfwRuleSectionUrl } from "@/lib/ngfwRuleLink";
import type { DiffEntry, DiffKind, DiffSide, DiffTable, DiffTableGroup, StageKey } from "@/lib/types";

/** Canonical reading order. New backend tables remain visible after it. */
const DIFF_TABLE_ORDER: readonly DiffTable[] = [
  "fw_pre_filter",
  "fw_forward",
  "fw_input",
  "fw_dnat",
  "fw_snat",
  "hw_mac",
  "hw_src_ip",
  "hw_dst_ip",
  "hw_src_dst_ip",
  "cf_rules",
  "shaper_rules",
  "ips_bypass",
  "aliases",
  "users",
  "dns_zones",
  "lan_networks",
  "ngfw_addresses",
];

export const TABLE_LABEL_KEY: Partial<Record<DiffTable, MessageKey>> = {
  fw_pre_filter: "snapshots.tableFwPreFilter",
  fw_forward: "snapshots.tableFwForward",
  fw_input: "snapshots.tableFwInput",
  fw_dnat: "snapshots.tableFwDnat",
  fw_snat: "snapshots.tableFwSnat",
  hw_mac: "snapshots.tableHwMac",
  hw_src_ip: "snapshots.tableHwSrcIp",
  hw_dst_ip: "snapshots.tableHwDstIp",
  hw_src_dst_ip: "snapshots.tableHwSrcDstIp",
  cf_rules: "snapshots.tableCfRules",
  shaper_rules: "snapshots.tableShaperRules",
  ips_bypass: "snapshots.tableIpsBypass",
  aliases: "snapshots.tableAliases",
  users: "snapshots.tableUsers",
  dns_zones: "snapshots.tableDnsZones",
  lan_networks: "snapshots.tableLanNetworks",
  ngfw_addresses: "snapshots.tableNgfwAddresses",
};

const STAGE_BY_DIFF_TABLE: Partial<Record<DiffTable, StageKey>> = {
  fw_pre_filter: "pre_filter",
  fw_forward: "firewall",
  fw_input: "firewall",
  fw_dnat: "dnat",
  fw_snat: "snat",
  hw_mac: "hw_filter",
  hw_src_ip: "hw_filter",
  hw_dst_ip: "hw_filter",
  hw_src_dst_ip: "hw_filter",
  cf_rules: "content_filter",
  shaper_rules: "rate_limit",
  ips_bypass: "ips",
};

export const DIFF_KIND_COLOR: Record<DiffKind, string> = {
  added: "var(--ok)",
  removed: "var(--bad)",
  changed: "var(--warn)",
  moved: "var(--info)",
};

/** State keys are an open backend vocabulary. Known keys get a translated
 * label, unknown keys deliberately fall back to their raw value. */
const STATE_LABEL_KEY: Record<string, MessageKey> = {
  "fw_state.enabled": "snapshots.state.fw_state",
  "cf_state.enabled": "snapshots.state.cf_state",
  "ips_state.enabled": "snapshots.state.ips_state",
  av_enabled: "snapshots.state.av_enabled",
  "shaper_state.enabled": "snapshots.state.shaper_state",
  "hw_settings.mode": "snapshots.state.hw_settings_mode",
  "fw_settings.automatic_snat_enabled": "snapshots.state.fw_settings_automatic_snat_enabled",
};

export function stateLabelKey(key: string): MessageKey | undefined {
  return STATE_LABEL_KEY[key];
}

export function groupDiffTables(tables: DiffTableGroup[]): DiffTableGroup[] {
  const known = DIFF_TABLE_ORDER.flatMap((table) => tables.filter((group) => group.table === table));
  const unknown = tables.filter((group) => !DIFF_TABLE_ORDER.includes(group.table));
  return [...known, ...unknown];
}

/** A removed rule is known to be absent in the later side, so linking to NGFW
 * would promise a target that may not exist. Imported-only ids are likewise
 * not linkable. */
export function ruleSectionLink({
  entry,
  table,
  before,
  after,
  server,
  port,
}: {
  entry: DiffEntry;
  table: DiffTable;
  before: DiffSide;
  after: DiffSide;
  server: string;
  port?: number;
}): string | null {
  const liveSide = linkableSide(entry, before, after);
  const stage = STAGE_BY_DIFF_TABLE[table];
  return liveSide && stage ? ngfwRuleSectionUrl(server, port, stage, entry.id) : null;
}

function linkableSide(entry: DiffEntry, before: DiffSide, after: DiffSide): DiffSide | null {
  if (entry.kind === "removed") return null;
  // An added id exists only in the later side. Do not fall back to the earlier
  // snapshot when that later side is imported: its id never existed on this
  // NGFW, even though the earlier side is otherwise linkable.
  if (entry.kind === "added") return after.source !== "imported" ? after : null;
  return after.source !== "imported" ? after : before.source !== "imported" ? before : null;
}

/** Safe, bounded stringification for unknown JSON values. The caller renders
 * the result as a React text node, never injected HTML. */
export function formatDiffValue(value: unknown): string {
  if (value === null || value === undefined) return "—";

  let text: string;
  if (typeof value === "string") text = value;
  else if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") text = String(value);
  else {
    try {
      text = JSON.stringify(value) ?? String(value);
    } catch {
      text = String(value);
    }
  }
  return text.length > 160 ? `${text.slice(0, 160)}…` : text;
}
