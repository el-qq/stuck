import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getLastServer, getRecentUrls, pushRecentUrl, setLastServer } from "../storage";

/**
 * lib/storage.ts: last used server address and
 * the 10 most recent check addresses, both in localStorage. happy-dom does
 * not expose window.localStorage, so an in-memory mock is installed on window
 * before every test — a clean slate each time.
 */

const LAST_SERVER_KEY = "stuck.lastServer";
const RECENT_URLS_KEY = "stuck.recentUrls";

function makeLocalStorageMock() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string): string | null => (store.has(key) ? store.get(key)! : null),
    setItem: (key: string, value: string): void => {
      store.set(key, String(value));
    },
    removeItem: (key: string): void => {
      store.delete(key);
    },
    clear: (): void => {
      store.clear();
    },
    get length(): number {
      return store.size;
    },
    key: (i: number): string | null => [...store.keys()][i] ?? null,
  };
}

beforeEach(() => {
  Object.defineProperty(window, "localStorage", {
    value: makeLocalStorageMock(),
    configurable: true,
    writable: true,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("lib/storage.ts — last server (FR-10.1)", () => {
  it("returns null when nothing was saved", () => {
    expect(getLastServer()).toBeNull();
  });

  it("round-trips the saved server address", () => {
    setLastServer("192.168.1.1");
    expect(getLastServer()).toBe("192.168.1.1");
  });

  it("overwrites the previous value", () => {
    setLastServer("192.168.1.1");
    setLastServer("ngfw.corp.local");
    expect(getLastServer()).toBe("ngfw.corp.local");
  });

  it("uses the stuck.lastServer key", () => {
    setLastServer("10.0.0.1");
    expect(window.localStorage.getItem(LAST_SERVER_KEY)).toBe("10.0.0.1");
  });

  it("swallows storage failures and returns null", () => {
    vi.spyOn(window.localStorage, "getItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });

    expect(getLastServer()).toBeNull();
  });

  it("swallows storage failures on write", () => {
    vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("quota exceeded");
    });

    expect(() => setLastServer("10.0.0.1")).not.toThrow();
  });
});

describe("lib/storage.ts — recent check addresses", () => {
  it("returns an empty list when nothing was saved", () => {
    expect(getRecentUrls()).toEqual([]);
  });

  it("prepends new addresses (newest first)", () => {
    pushRecentUrl("a.com");
    pushRecentUrl("b.com");
    const result = pushRecentUrl("c.com");

    expect(result).toEqual(["c.com", "b.com", "a.com"]);
    expect(getRecentUrls()).toEqual(["c.com", "b.com", "a.com"]);
  });

  it("keeps at most 10 entries", () => {
    for (const u of ["1.com", "2.com", "3.com", "4.com", "5.com", "6.com", "7.com", "8.com", "9.com", "10.com", "11.com", "12.com"]) {
      pushRecentUrl(u);
    }

    const result = getRecentUrls();
    expect(result).toHaveLength(10);
    expect(result).toEqual(["12.com", "11.com", "10.com", "9.com", "8.com", "7.com", "6.com", "5.com", "4.com", "3.com"]);
  });

  it("dedupes: re-entering an address moves it to the top without duplication", () => {
    pushRecentUrl("a.com");
    pushRecentUrl("b.com");
    pushRecentUrl("c.com");

    const result = pushRecentUrl("a.com");

    expect(result).toEqual(["a.com", "c.com", "b.com"]);
    expect(result.filter((u) => u === "a.com")).toHaveLength(1);
  });

  it("trims the address before saving and dedupes on the trimmed value", () => {
    pushRecentUrl("a.com");
    const result = pushRecentUrl("  a.com  ");

    expect(result).toEqual(["a.com"]);
  });

  it("ignores empty and whitespace-only input", () => {
    pushRecentUrl("a.com");

    expect(pushRecentUrl("")).toEqual(["a.com"]);
    expect(pushRecentUrl("   ")).toEqual(["a.com"]);
    expect(getRecentUrls()).toEqual(["a.com"]);
  });

  it("supports addresses with an explicit port (FR-10.10)", () => {
    const result = pushRecentUrl("example.com:12345");
    expect(result).toEqual(["example.com:12345"]);
  });

  it("uses the stuck.recentUrls key with a JSON array value", () => {
    pushRecentUrl("a.com");
    expect(JSON.parse(window.localStorage.getItem(RECENT_URLS_KEY)!)).toEqual(["a.com"]);
  });

  it("returns [] for corrupted JSON in storage", () => {
    window.localStorage.setItem(RECENT_URLS_KEY, "{not json");
    expect(getRecentUrls()).toEqual([]);
  });

  it("returns [] when the stored value is not an array", () => {
    window.localStorage.setItem(RECENT_URLS_KEY, JSON.stringify({ a: 1 }));
    expect(getRecentUrls()).toEqual([]);
  });

  it("filters out non-string entries from stored data", () => {
    window.localStorage.setItem(RECENT_URLS_KEY, JSON.stringify(["a.com", 42, null, "b.com", { x: 1 }]));
    expect(getRecentUrls()).toEqual(["a.com", "b.com"]);
  });

  it("caps oversized stored lists at 10 on read", () => {
    window.localStorage.setItem(RECENT_URLS_KEY, JSON.stringify(["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]));
    expect(getRecentUrls()).toEqual(["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
  });

  it("swallows storage failures on write and still returns the computed list", () => {
    pushRecentUrl("a.com");
    vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("quota exceeded");
    });

    expect(pushRecentUrl("b.com")).toEqual(["b.com", "a.com"]);
  });
});
