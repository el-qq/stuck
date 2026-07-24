import { MessageKey } from "@/i18n/en";
import { Protocol } from "./types";

/**
 * Fixed order for the NGFW firewall protocol selector, shared by the trace
 * ("Проверка трафика") and access-compare forms so both tabs offer the exact
 * same 8 choices in the exact same order. "any" is first because it is both
 * the wildcard option and the request default.
 */
export const PROTOCOL_OPTIONS: readonly Protocol[] = ["any", "ah", "esp", "gre", "icmp", "tcp", "udp", "tcp_udp"];

export const DEFAULT_PROTOCOL: Protocol = "any";

/**
 * Display label for a protocol value. The acronyms (AH/ESP/GRE/ICMP/TCP/UDP)
 * and the "TCP/UDP" combo are deliberately literal, not translated — they
 * read the same in every locale. Only the "any" wildcard is localized.
 */
export function protocolDisplayLabel(protocol: Protocol, t: (key: MessageKey) => string): string {
  if (protocol === "any") return t("protocol.any");
  if (protocol === "tcp_udp") return "TCP/UDP";
  return protocol.toUpperCase();
}
