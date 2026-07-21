import { describe, expect, it } from "vitest";
import { runDemoTrace, DEFAULT_DEMO_TARGET } from "../demoData";
import { createTraceExport, defaultTraceExportFilename, TRACE_EXPORT_FORMAT } from "../traceExport";
import type { MessageKey } from "@/i18n/en";
import type { TraceResponse } from "../types";

const t = ((key: MessageKey) => key) as (key: MessageKey) => string;
const EXPORTED_AT = new Date("2026-07-21T10:11:12.345Z");

describe("trace export", () => {
  it("creates a self-describing ticket attachment from the complete trace", () => {
    const trace = runDemoTrace(DEFAULT_DEMO_TARGET, null, t);

    expect(createTraceExport(trace, EXPORTED_AT)).toEqual({
      format: TRACE_EXPORT_FORMAT,
      exported_at: "2026-07-21T10:11:12.345Z",
      trace,
    });
  });

  it("allowlists trace fields and drops unexpected session-like data", () => {
    const trace = {
      ...runDemoTrace(DEFAULT_DEMO_TARGET, null, t),
      stuck_session: "must-not-be-exported",
      ngfw_cookie: "must-not-be-exported",
    } as TraceResponse & { stuck_session: string; ngfw_cookie: string };

    const attachment = createTraceExport(trace, EXPORTED_AT);
    expect(attachment).not.toHaveProperty("stuck_session");
    expect(attachment).not.toHaveProperty("ngfw_cookie");
    expect(JSON.stringify(attachment)).not.toContain("must-not-be-exported");
  });

  it("uses a safe, timestamped JSON filename", () => {
    expect(defaultTraceExportFilename("2001:db8::1", EXPORTED_AT)).toBe("trace-2001_db8__1-2026-07-21T10-11-12-345Z.json");
    expect(defaultTraceExportFilename("", EXPORTED_AT)).toBe("trace-target-2026-07-21T10-11-12-345Z.json");
  });
});
