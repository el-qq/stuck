import { downloadBlob } from "./download";
import { StageDetail, TraceResponse } from "./types";

/** Stable, self-describing format for a single trace attachment. */
export const TRACE_EXPORT_FORMAT = "stuck.trace/v1";

export interface TraceExport {
  format: typeof TRACE_EXPORT_FORMAT;
  exported_at: string;
  trace: TraceResponse;
}

/**
 * Builds the ticket attachment from an allowlist of the public trace fields.
 * Do not export a session object here: it can contain administrator and
 * connection state that is unrelated to a traffic diagnosis.
 */
export function createTraceExport(trace: TraceResponse, exportedAt = new Date()): TraceExport {
  return {
    format: TRACE_EXPORT_FORMAT,
    exported_at: exportedAt.toISOString(),
    trace: {
      target: {
        input: trace.target.input,
        normalized_url: trace.target.normalized_url,
        host: trace.target.host,
        resolved_ip: trace.target.resolved_ip,
        source_ip: trace.target.source_ip,
        dst_port: trace.target.dst_port,
        protocol: trace.target.protocol,
        effective_destination_ip: trace.target.effective_destination_ip,
        effective_destination_port: trace.target.effective_destination_port,
      },
      user: trace.user ? { id: trace.user.id, name: trace.user.name, login: trace.user.login } : null,
      categories: [...trace.categories],
      stages: trace.stages.map((stage) => ({
        key: stage.key,
        order: stage.order,
        title_key: stage.title_key,
        status: stage.status,
        ...(stage.detail ? { detail: copyStageDetail(stage.detail) } : {}),
      })),
      summary: {
        reached_destination: trace.summary.reached_destination,
        blocked_at: trace.summary.blocked_at,
        verdict: trace.summary.verdict,
      },
      rules_updated_at: trace.rules_updated_at,
    },
  };
}

/** Fallback export filename: trace-<host>-<timestamp>.json. */
export function defaultTraceExportFilename(host: string, exportedAt = new Date()): string {
  const safeHost = host.replace(/[^a-zA-Z0-9._-]/g, "_") || "target";
  const timestamp = exportedAt.toISOString().replace(/[:.]/g, "-");
  return `trace-${safeHost}-${timestamp}.json`;
}

/** Downloads the current trace without contacting STUCK or NGFW again. */
export function downloadTraceExport(trace: TraceResponse, exportedAt = new Date()): void {
  const payload = createTraceExport(trace, exportedAt);
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" });
  downloadBlob(blob, defaultTraceExportFilename(trace.target.host, exportedAt));
}

function copyStageDetail(detail: StageDetail): StageDetail {
  return {
    ...(detail.rule_id !== undefined ? { rule_id: detail.rule_id } : {}),
    ...(detail.rule_name !== undefined ? { rule_name: detail.rule_name } : {}),
    ...(detail.action !== undefined ? { action: detail.action } : {}),
    ...(detail.matched_category !== undefined ? { matched_category: detail.matched_category } : {}),
    ...(detail.redirect_url !== undefined ? { redirect_url: detail.redirect_url } : {}),
    ...(detail.reason_key !== undefined ? { reason_key: detail.reason_key } : {}),
    ...(detail.module_enabled !== undefined ? { module_enabled: detail.module_enabled } : {}),
    ...(detail.speed_kbps !== undefined ? { speed_kbps: detail.speed_kbps } : {}),
    ...(detail.limit_scope !== undefined ? { limit_scope: detail.limit_scope } : {}),
    ...(detail.resolved_ip !== undefined ? { resolved_ip: detail.resolved_ip } : {}),
    ...(detail.firewall_table !== undefined ? { firewall_table: detail.firewall_table } : {}),
    ...(detail.translated_destination_ip !== undefined ? { translated_destination_ip: detail.translated_destination_ip } : {}),
    ...(detail.translated_destination_port !== undefined ? { translated_destination_port: detail.translated_destination_port } : {}),
    ...(detail.translated_source_ip !== undefined ? { translated_source_ip: detail.translated_source_ip } : {}),
  };
}
