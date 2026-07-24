import type { MessageKey } from "@/i18n/en";
import { ApiError } from "@/lib/errors";
import { CompareSide, StageClassification } from "@/lib/types";

/** Known per-side reasons a `compare_side_invalid` response can carry
 * (docs/source/comparison.md §3.i, cases 2-4). An unrecognized reason (a
 * future backend addition) falls back to the generic `errors.compare_side_invalid`
 * message instead of showing nothing or a raw key. */
const REASON_KEY: Record<string, MessageKey> = {
  unknown_user: "compare.reason.unknown_user",
  multiple_source_ips: "compare.reason.multiple_source_ips",
  source_ip_not_assigned: "compare.reason.source_ip_not_assigned",
  invalid_source_ip: "compare.reason.invalid_source_ip",
};

/** Maps a `compare_side_invalid` ApiError to its per-reason message key, or
 * `null` when the code/reason is not one of ours (caller falls back to the
 * generic `errors.compare_side_invalid` translation). */
export function compareSideReasonKey(err: ApiError): MessageKey | null {
  if (err.code !== "compare_side_invalid") return null;
  const reason = err.details?.reason;
  if (typeof reason !== "string") return null;
  return REASON_KEY[reason] ?? null;
}

/** The side this `compare_side_invalid` error is about, or `null` if the
 * envelope is missing/malformed `details.side` (treated as a generic error —
 * never guessed, per invariant honesty about incomplete context). */
export function compareErrorSide(err: ApiError): "a" | "b" | null {
  const side = err.details?.side;
  return side === "a" || side === "b" ? side : null;
}

/** Human label for a compared side's subject: the user's name (with their
 * source IP alongside it when known), a bare source IP, or the localized
 * "no specific subject" placeholder — never a raw null/undefined. */
export function compareSubjectLabel(side: CompareSide, t: (key: MessageKey) => string): string {
  if (side.subject.user) {
    return side.subject.source_ip ? `${side.subject.user.name} (${side.subject.source_ip})` : side.subject.user.name;
  }
  if (side.subject.source_ip) return side.subject.source_ip;
  return t("compare.noSubject");
}

/** Row-level tone for a stage's diff classification — deliberately distinct
 * from `frontend/lib/stages.ts` `STATUS_TONE`: that colors one side's raw
 * stage status, this colors the DIFF verdict between both sides. Honesty
 * (invariant №7): `incomparable` must never look like a proven `divergent`. */
export type ClassificationTone = "neutral" | "bad" | "warn";

export const CLASSIFICATION_TONE: Record<StageClassification, ClassificationTone> = {
  same: "neutral",
  divergent: "bad",
  incomparable: "warn",
};

export const CLASSIFICATION_LABEL_KEY: Record<StageClassification, MessageKey> = {
  same: "compare.classificationSame",
  divergent: "compare.classificationDivergent",
  incomparable: "compare.classificationIncomparable",
};
