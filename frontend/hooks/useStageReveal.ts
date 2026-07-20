import { useCallback, useEffect, useRef, useState } from "react";
import { TraceStage } from "@/lib/types";
import { useMediaQuery } from "./useMediaQuery";

const STEP_MS = 420;

/**
 * Drives the pipeline animation (FR-5): stages reveal one at a time in
 * order; the first `block` status stops the "flowing" effect (the
 * remaining na/skip stages still render immediately after, per contract
 * invariant that every contract stage is always present).
 */
export function useStageReveal(stages: TraceStage[] | null, animationEnabled: boolean) {
  const reduceMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const compactLayout = useMediaQuery("(max-width: 959px)");
  const showImmediately = !animationEnabled || reduceMotion || compactLayout;
  const [revealCount, setRevealCount] = useState(() => (showImmediately ? (stages?.length ?? 0) : 0));
  const [flowing, setFlowing] = useState(() => !showImmediately && !!stages?.length);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (!stages || stages.length === 0) {
      setRevealCount(0);
      setFlowing(false);
      return;
    }
    if (showImmediately) {
      setRevealCount(stages.length);
      setFlowing(false);
      return;
    }
    setRevealCount(0);
    setFlowing(true);
    const blockIdx = stages.findIndex((s) => s.status === "block");
    const stopAt = blockIdx === -1 ? stages.length : blockIdx + 1;
    let i = 0;
    timerRef.current = setInterval(() => {
      i += 1;
      if (i >= stopAt) {
        setRevealCount(stages.length);
        setFlowing(false);
        if (timerRef.current) clearInterval(timerRef.current);
      } else {
        setRevealCount(i);
      }
    }, STEP_MS);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [stages, showImmediately]);

  const skip = useCallback(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    setRevealCount(stages?.length ?? 0);
    setFlowing(false);
  }, [stages]);

  const done = stages ? revealCount >= stages.length : false;

  // Iteration 3 (#6): the "replay animation" control was removed by customer
  // request; only "skip" remains.
  return { revealCount, flowing, done, skip, animateStages: !showImmediately };
}
