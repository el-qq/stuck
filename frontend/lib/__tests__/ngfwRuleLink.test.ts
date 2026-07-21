import { describe, expect, it } from "vitest";
import { ngfwRuleSectionUrl } from "../ngfwRuleLink";

describe("ngfwRuleSectionUrl", () => {
  it.each([
    ["firewall", "https://ngfw.example:8443/#/settings/access-rules/firewall"],
    ["content_filter", "https://ngfw.example:8443/#/settings/access-rules/content-filter"],
    ["ips", "https://ngfw.example:8443/#/settings/access-rules/ips"],
  ] as const)("links %s rules to the related admin section", (stage, expected) => {
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, stage, "rule.1")).toBe(expected);
  });

  it("does not expose a link without a matched rule or supported section", () => {
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, "firewall", undefined)).toBeNull();
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, "dns", "rule.1")).toBeNull();
  });
});
