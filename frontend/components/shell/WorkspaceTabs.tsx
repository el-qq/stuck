"use client";

import React, { useLayoutEffect, useRef } from "react";

/**
 * Standalone workspace tab bar shown BELOW the header (and the demo banner),
 * exactly where it visually belongs — but sticky right under the sticky
 * header, so scrolling the results never hides the tabs.
 *
 * Its measured height is published as ``--stuck-tabs-h`` so the sticky side
 * panels offset below it (Header.tsx publishes ``--stuck-header-h`` the same
 * way). On unmount (e.g. hygiene disabled) the offset returns to zero.
 */
export function WorkspaceTabs({ ariaLabel, children }: { ariaLabel: string; children: React.ReactNode }) {
  const ref = useRef<HTMLElement>(null);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const apply = () => document.documentElement.style.setProperty("--stuck-tabs-h", `${el.offsetHeight}px`);
    apply();
    const observer = new ResizeObserver(apply);
    observer.observe(el);
    return () => {
      observer.disconnect();
      document.documentElement.style.setProperty("--stuck-tabs-h", "0px");
    };
  }, []);

  return (
    <nav ref={ref} className="workspace-tabs" role="tablist" aria-label={ariaLabel}>
      {children}
    </nav>
  );
}
