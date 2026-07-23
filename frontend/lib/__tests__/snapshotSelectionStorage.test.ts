import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getSnapshotSelection, setSnapshotSelection, snapshotSelectionStorageKey } from "../snapshotSelectionStorage";

function makeSessionStorageMock() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string): string | null => (store.has(key) ? store.get(key)! : null),
    setItem: (key: string, value: string): void => {
      store.set(key, String(value));
    },
    removeItem: (key: string): void => {
      store.delete(key);
    },
  };
}

beforeEach(() => {
  Object.defineProperty(window, "sessionStorage", {
    value: makeSessionStorageMock(),
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("snapshotSelectionStorage", () => {
  it("round-trips only the selected ids and active side for one binding", () => {
    setSnapshotSelection("admin.readonly", "ngfw.example", {
      beforeId: "snapshot-before",
      afterId: "current",
      activeSide: "after",
    });

    expect(getSnapshotSelection("admin.readonly", "ngfw.example")).toEqual({
      beforeId: "snapshot-before",
      afterId: "current",
      activeSide: "after",
    });
  });

  it("isolates selections between administrator/NGFW pairs", () => {
    setSnapshotSelection("admin.a", "ngfw.example", {
      beforeId: "snapshot-a",
      afterId: "current",
      activeSide: "before",
    });

    expect(getSnapshotSelection("admin.b", "ngfw.example")).toBeNull();
    expect(getSnapshotSelection("admin.a", "other-ngfw.example")).toBeNull();
  });

  it("rejects malformed storage instead of trusting arbitrary page data", () => {
    window.sessionStorage.setItem(
      snapshotSelectionStorageKey("admin", "ngfw.example"),
      JSON.stringify({ beforeId: 42, afterId: "current", activeSide: "after" }),
    );

    expect(getSnapshotSelection("admin", "ngfw.example")).toBeNull();
  });

  it("swallows unavailable session storage", () => {
    vi.spyOn(window.sessionStorage, "setItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });

    expect(() => setSnapshotSelection("admin", "ngfw.example", { beforeId: "one", afterId: "two", activeSide: "before" })).not.toThrow();
  });
});
