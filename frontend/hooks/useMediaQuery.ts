"use client";

import { useEffect, useState } from "react";

function matches(query: string): boolean {
  return typeof window !== "undefined" && window.matchMedia(query).matches;
}
/** Reactive matchMedia wrapper with the correct value on the first client render. */
export function useMediaQuery(query: string): boolean {
  const [matched, setMatched] = useState(() => matches(query));

  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setMatched(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [query]);

  return matched;
}
