/**
 * The locale registry: which languages exist, how they are labelled, which
 * dictionary backs each one, and how a BCP-47 tag from the browser (or from
 * `localStorage`) resolves to one of them.
 *
 * Everything that enumerates locales — the provider, the settings selector and
 * the locale test — derives from `SUPPORTED_LOCALES` and `DICTIONARIES` here.
 * Registering a language in one place is what keeps a new locale from being
 * silently untested or unreachable in the UI.
 */
import { en } from "./en";
import { es } from "./es";
import { ru } from "./ru";
import { kk } from "./kk";
import { ms } from "./ms";
import { fr } from "./fr";
import { be } from "./be";
import { ky } from "./ky";
import { hy } from "./hy";
import { uz } from "./uz";
import { ptBR } from "./pt-BR";
import { id } from "./id";
import { tr } from "./tr";
import { vi } from "./vi";
import type { LocaleDictionary } from "./core";

export type Locale = "en" | "es" | "ru" | "kk" | "ms" | "fr" | "be" | "ky" | "hy" | "uz" | "pt-BR" | "id" | "tr" | "vi";

/** Target market a language is carried for; it orders the registry below. */
export type LocaleRegion = "global" | "cis" | "europe" | "latam" | "apac" | "mena";

/** See `core.ts` — "core" locales may fall back to English outside the core key set. */
export type LocaleTier = "full" | "core";

export interface LocaleDescriptor {
  code: Locale;
  /** Endonym — the settings list shows every language in its own language. */
  nativeName: string;
  region: LocaleRegion;
  tier: LocaleTier;
}

/**
 * Order matters twice: it is the order of the settings list, and `matchLocale`
 * resolves a bare language tag to the first regional variant listed for that
 * language (`pt` → `pt-BR`). The list runs English first, then by market: CIS,
 * Europe, Latin America, Asia-Pacific, Middle East.
 *
 * `es` is deliberately a single neutral Latin American Spanish (es-419) rather
 * than one dictionary per country, and it keeps the plain `es` code so that
 * every Spanish browser tag still resolves to it.
 */
export const SUPPORTED_LOCALES: readonly LocaleDescriptor[] = [
  { code: "en", nativeName: "English", region: "global", tier: "full" },
  { code: "ru", nativeName: "Русский", region: "cis", tier: "full" },
  // be/ky/hy translate the core set and part of the long tail; they used to
  // spread `...en` to look complete, which is what the tier now records.
  { code: "be", nativeName: "Беларуская", region: "cis", tier: "core" },
  { code: "kk", nativeName: "Қазақша", region: "cis", tier: "full" },
  { code: "ky", nativeName: "Кыргызча", region: "cis", tier: "core" },
  { code: "uz", nativeName: "Oʻzbekcha", region: "cis", tier: "core" },
  { code: "hy", nativeName: "Հայերեն", region: "cis", tier: "core" },
  { code: "fr", nativeName: "Français", region: "europe", tier: "full" },
  { code: "es", nativeName: "Español (Latinoamérica)", region: "latam", tier: "full" },
  { code: "pt-BR", nativeName: "Português (Brasil)", region: "latam", tier: "core" },
  { code: "id", nativeName: "Bahasa Indonesia", region: "apac", tier: "core" },
  { code: "ms", nativeName: "Bahasa Melayu", region: "apac", tier: "full" },
  { code: "vi", nativeName: "Tiếng Việt", region: "apac", tier: "core" },
  { code: "tr", nativeName: "Türkçe", region: "mena", tier: "core" },
];

export const DICTIONARIES: Record<Locale, LocaleDictionary> = {
  en,
  ru,
  be,
  kk,
  ky,
  uz,
  hy,
  fr,
  es,
  "pt-BR": ptBR,
  id,
  ms,
  vi,
  tr,
};

export const DEFAULT_LOCALE: Locale = "en";

/** Canonical region order; the registry above is listed in it. */
export const LOCALE_REGION_ORDER: readonly LocaleRegion[] = ["global", "cis", "europe", "latam", "apac", "mena"];

function normalizeTag(tag: string): string {
  return tag.trim().toLowerCase().replace(/_/g, "-");
}

/**
 * Resolve one language tag in two modes, in this order:
 *
 * 1. **exact tag** — `pt-BR`, `PT-br` and `pt_BR` all select `pt-BR`;
 * 2. **base language** — anything else falls back to the first registered
 *    locale with the same primary subtag, so `pt`, `pt-PT` and `pt-AO` select
 *    `pt-BR`, and `es-MX`/`es-ES` select `es`.
 *
 * Mode 2 is what the old two-character slice did, and it is why it could never
 * distinguish two variants of one language; mode 1 is what makes a regional
 * dictionary addressable at all. Returns `null` for an unsupported tag so the
 * caller can keep trying lower-priority candidates.
 */
export function matchLocale(tag: string): Locale | null {
  const normalized = normalizeTag(tag);
  if (!normalized) return null;

  const exact = SUPPORTED_LOCALES.find((entry) => entry.code.toLowerCase() === normalized);
  if (exact) return exact.code;

  const base = normalized.split("-")[0]!;
  const byBase = SUPPORTED_LOCALES.find((entry) => entry.code.toLowerCase().split("-")[0] === base);
  return byBase ? byBase.code : null;
}

/** First supported locale among ordered browser candidates, or `null`. */
export function resolveLocale(tags: readonly (string | undefined | null)[]): Locale | null {
  for (const tag of tags) {
    if (!tag) continue;
    const match = matchLocale(tag);
    if (match) return match;
  }
  return null;
}
