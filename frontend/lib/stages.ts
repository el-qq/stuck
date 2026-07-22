import { StageKey, StageStatus } from "./types";

/**
 * Node badges for the pipeline visualization. Abbreviations are kept
 * language-neutral (technical shorthand, not translated) so they read the
 * same in every locale; the full stage name comes from `title_key` via i18n.
 */
export const STAGE_ABBR: Record<StageKey, string> = {
  hw_filter: "HW",
  pre_filter: "PRE",
  rate_limit: "RL",
  dns: "DNS",
  dnat: "DNAT",
  content_filter: "CF",
  antivirus: "AV",
  firewall: "FW",
  app_control: "APP",
  ips: "IPS",
  snat: "SNAT",
  destination: "DST",
};

export type StatusTone = "ok" | "bad" | "warn" | "info" | "skip";

/** Maps stage statuses onto semantic tokens; `info` never follows the user accent. */
export const STATUS_TONE: Record<StageStatus, StatusTone> = {
  pass: "ok",
  block: "bad",
  limited: "warn",
  resolved: "info",
  active: "info",
  applied: "info",
  conditional: "info",
  skip: "skip",
  bypass: "warn",
  unknown: "warn",
  na: "skip",
};
