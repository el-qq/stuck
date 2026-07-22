import { useCallback } from "react";
import { useI18n } from "@/i18n";
import { ApiError } from "@/lib/errors";
import { MessageKey } from "@/i18n/en";

/**
 * Maps a contract error code (docs/API_CONTRACT.md) to a localized,
 * human-readable message. Every code has a translation in all supported locales
 * (enforced at compile time by i18n/*.ts); unknown codes were already
 * normalized to "ngfw_error" in lib/errors.ts, so this never throws.
 *
 * The returned function is memoized (``t`` itself is stable per locale), so it
 * is safe to list as a dependency of effects/callbacks without re-triggering
 * them on every render.
 */
export function useApiErrorMessage() {
  const { t } = useI18n();
  return useCallback((err: ApiError): string => t(`errors.${err.code}` as MessageKey), [t]);
}
