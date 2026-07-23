"use client";

import { useCallback } from "react";
import { useToast } from "@/contexts/ToastContext";
import { useI18n } from "@/i18n";

/** Shows feedback for an intentionally inert demo action without giving it
 * access to a backend callback. `aria-disabled` keeps the control honest to
 * assistive technology while still allowing this explanatory click. */
export function useDemoUnavailableNotice(unavailable: boolean) {
  const { t } = useI18n();
  const toast = useToast();

  return useCallback(() => {
    if (unavailable) toast.show(t("demo.backendActionsUnavailable"), "info");
  }, [t, toast, unavailable]);
}
