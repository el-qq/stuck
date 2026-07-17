"use client";

import { RefObject, useEffect } from "react";

/** Move a compact-layout user from the form to a newly produced result. */
export function useMobileResultScroll(resultRef: RefObject<HTMLElement | null>, trigger: unknown): void {
  useEffect(() => {
    if (!trigger || !window.matchMedia("(max-width: 959px)").matches) return;
    let innerFrame = 0;
    const frame = window.requestAnimationFrame(() => {
      innerFrame = window.requestAnimationFrame(() => {
        const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        resultRef.current?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
      });
    });
    return () => {
      window.cancelAnimationFrame(frame);
      window.cancelAnimationFrame(innerFrame);
    };
  }, [resultRef, trigger]);
}
