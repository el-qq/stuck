"use client";

import { DEMO_ACCESS_COMPARE } from "@/lib/demoData";
import { CompareResponse } from "@/lib/types";

export interface DemoAccessCompareState {
  response: CompareResponse;
}

/** Fully local adapter for the access-compare tab (docs/source/comparison.md
 * §4 "Демо"). Unlike `useDemoRuleSnapshots` (which lets the administrator
 * pick any of a few fixed sides to re-diff), this tab has no interactive
 * subject pickers in demo mode — the two illustrative subjects are fixed, so
 * the one precomputed `CompareResponse` covers every classification
 * (same/divergent/incomparable), `primary_divergence` and per-side context
 * without contacting a backend. It feeds the exact same `AccessCompareView`
 * the live workspace renders. */
export function useDemoAccessCompare(): DemoAccessCompareState {
  return { response: DEMO_ACCESS_COMPARE };
}
