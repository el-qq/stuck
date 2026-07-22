import { describe, expect, it } from "vitest";
import { ngfwRuleSectionUrl } from "../ngfwRuleLink";

describe("ngfwRuleSectionUrl", () => {
  it.each([
    ["hw_filter", "https://ngfw.example:8443/#/firewall/hardware-filtering"],
    ["pre_filter", "https://ngfw.example:8443/#/firewall/prefiltering"],
    ["dnat", "https://ngfw.example:8443/#/firewall/dnat"],
    ["firewall", "https://ngfw.example:8443/#/firewall/firewall-users"],
    ["content_filter", "https://ngfw.example:8443/#/settings/access-rules/content-filter"],
    ["ips", "https://ngfw.example:8443/#/settings/access-rules/ips"],
    ["snat", "https://ngfw.example:8443/#/firewall/snat"],
  ] as const)("links %s rules to the related admin section", (stage, expected) => {
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, stage, "rule.1")).toBe(expected);
  });

  it("does not expose a link without a matched rule or supported section", () => {
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, "firewall", undefined)).toBeNull();
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, "firewall", "   ")).toBeNull();
    expect(ngfwRuleSectionUrl("ngfw.example", 8443, "dns", "rule.1")).toBeNull();
  });

  it.each([0, -1, 8443.5, 65536, Number.NaN])("does not expose a link with an invalid NGFW port: %s", (port) => {
    expect(ngfwRuleSectionUrl("ngfw.example", port, "firewall", "rule.1")).toBeNull();
  });
});
