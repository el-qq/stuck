import { describe, expect, it } from "vitest";
import { readFileAsText } from "../fileRead";

/**
 * lib/fileRead.ts — the `FileReader` wrapper used by snapshot import
 * (docs/source/snapshots.md fork h.5, decision №10: file only, no textarea).
 */
describe("lib/fileRead.ts", () => {
  it("resolves with the file's text content", async () => {
    const file = new File(['{"format":"stuck.rules/v2"}'], "export.json", { type: "application/json" });
    const text = await readFileAsText(file);
    expect(text).toBe('{"format":"stuck.rules/v2"}');
  });

  it("resolves with an empty string for an empty file", async () => {
    const file = new File([], "empty.json", { type: "application/json" });
    const text = await readFileAsText(file);
    expect(text).toBe("");
  });

  it("preserves non-ASCII content", async () => {
    const file = new File(["Комментарий"], "comment.json", { type: "application/json" });
    const text = await readFileAsText(file);
    expect(text).toBe("Комментарий");
  });
});
