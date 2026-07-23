import { describe, expect, it } from "vitest";
import type { DiffEntry, DiffSide, DiffTableGroup } from "@/lib/types";
import { formatDiffValue, groupDiffTables, ruleSectionLink, stateLabelKey } from "../snapshotDiffPresentation";

const manualSide: DiffSide = {
  id: "saved-1",
  created_at: "2026-07-23T10:00:00Z",
  rules_updated_at: "2026-07-23T10:00:00Z",
  comment: null,
  source: "manual",
};

const currentSide: DiffSide = { ...manualSide, id: "current", source: "current" };

function entry(kind: DiffEntry["kind"]): DiffEntry {
  return {
    kind,
    id: "rule-1",
    name: null,
    position_a: 1,
    position_b: kind === "removed" ? null : 1,
  };
}

describe("snapshot diff presentation", () => {
  it("never creates an NGFW deep link for a removed rule", () => {
    expect(
      ruleSectionLink({
        entry: entry("removed"),
        table: "fw_forward",
        before: manualSide,
        after: currentSide,
        server: "ngfw.example",
        port: 8443,
      }),
    ).toBeNull();
  });

  it("only links a rule that exists on a non-imported side", () => {
    expect(
      ruleSectionLink({
        entry: entry("added"),
        table: "fw_forward",
        before: manualSide,
        after: currentSide,
        server: "ngfw.example",
        port: 8443,
      }),
    ).toBe("https://ngfw.example:8443/#/firewall/firewall-users");

    expect(
      ruleSectionLink({
        entry: entry("added"),
        table: "fw_forward",
        before: manualSide,
        after: { ...currentSide, source: "imported" },
        server: "ngfw.example",
        port: 8443,
      }),
    ).toBeNull();
  });

  it("maps the exact backend state keys and leaves future keys visible", () => {
    expect(stateLabelKey("fw_state.enabled")).toBe("snapshots.state.fw_state");
    expect(stateLabelKey("cf_state.enabled")).toBe("snapshots.state.cf_state");
    expect(stateLabelKey("ips_state.enabled")).toBe("snapshots.state.ips_state");
    expect(stateLabelKey("shaper_state.enabled")).toBe("snapshots.state.shaper_state");
    expect(stateLabelKey("future.module.setting")).toBeUndefined();
  });

  it("keeps the canonical table order and appends an unknown backend table", () => {
    const unknown = { table: "future_table", entries: [] } as unknown as DiffTableGroup;
    const ordered = groupDiffTables([{ table: "users", entries: [] }, unknown, { table: "fw_forward", entries: [] }]);
    expect(ordered.map((group) => group.table)).toEqual(["fw_forward", "users", "future_table"]);
  });

  it("formats untrusted values as bounded plain text", () => {
    expect(formatDiffValue('<img src=x onerror="alert(1)">')).toBe('<img src=x onerror="alert(1)">');
    expect(formatDiffValue("x".repeat(161))).toHaveLength(161);
  });
});
