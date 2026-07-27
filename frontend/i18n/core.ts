/**
 * Translation tiers.
 *
 * Every locale used to be complete or absent: `Record<MessageKey, string>`,
 * enforced by both TypeScript and the locale test. That cost scales with the
 * number of languages — each new feature multiplied its strings by the locale
 * count — and it made "one more market language" an expensive decision.
 *
 * There are now two tiers:
 *
 * - **full** — every key is translated (`FullDictionary`). The historical
 *   locales stay here, and this is the target state for any locale that a
 *   customer actually runs the product in.
 * - **core** — only `CORE_MESSAGE_KEYS` is mandatory (`CoreDictionary`). The
 *   rest may be omitted and renders in English via the fallback chain in
 *   `index.tsx` (`t()`/`tOptional()` read `en` when the active dictionary has
 *   no entry). A core locale is a real, shippable locale, not a stub: the tier
 *   only decides how much of the long tail is allowed to stay English.
 *
 * `CORE_MESSAGE_KEYS` is therefore not "the important strings" in the abstract
 * — it is the set a user cannot avoid seeing: sign-in, the header and tab bar,
 * settings, session/error messages, the check form, the pipeline stage names,
 * their statuses and the verdict. Long explanatory copy (rule hygiene
 * findings, snapshot diffs, per-stage `reason.*` sentences, the rules-loading
 * popup, the access diagnostic) is deliberately outside it: those strings are
 * long, technical and change often, and an English sentence there is a much
 * smaller problem than a stale or machine-translated one.
 *
 * Adding a key to this list makes it mandatory for every core locale, so the
 * locale test will fail until each of them translates it. That is the intended
 * pressure — keep the list to what the name promises.
 */
import type { MessageKey } from "./en";

export const CORE_MESSAGE_KEYS = [
  // ---- common chrome ----
  "common.appName",
  "common.appTagline",
  "common.loading",
  "common.cancel",
  "common.save",
  "common.close",
  "common.ok",
  "common.retry",
  "common.showDetails",
  "common.hideDetails",
  "common.or",
  "common.openNgfwSection",

  // ---- demo mode ----
  "demo.button",
  "demo.bannerTitle",
  "demo.bannerText",
  "demo.exit",
  "demo.targetsLabel",
  "demo.backendActionUnavailable",
  "demo.backendActionsUnavailable",

  // ---- sign-in and two-factor ----
  "login.title",
  "login.subtitle",
  "login.serverLabel",
  "login.serverPlaceholder",
  "login.readonlyHint",
  "login.unrestrictedNgfwWarning",
  "login.sessionExpiredNotice",
  "login.twoFactorResetNotice",
  "login.showPassword",
  "login.hidePassword",
  "login.loginLabel",
  "login.loginPlaceholder",
  "login.passwordLabel",
  "login.passwordPlaceholder",
  "login.submit",
  "login.submitting",
  "login.footnote",
  "login.validation.serverRequired",
  "login.validation.serverFormat",
  "login.validation.loginRequired",
  "login.validation.passwordRequired",
  "twoFactor.title",
  "twoFactor.subtitle",
  "twoFactor.codeLabel",
  "twoFactor.codePlaceholder",
  "twoFactor.expiresIn",
  "twoFactor.expired",
  "twoFactor.submit",
  "twoFactor.submitting",
  "twoFactor.cancel",
  "twoFactor.validation.codeRequired",

  // ---- header ----
  "header.rulesLoaded",
  "header.rulesNotLoaded",
  "header.refresh",
  "header.refreshing",
  "header.exportRules",
  "header.exporting",
  "header.settings",
  "header.logout",
  "header.sessionExpires",

  // ---- tab bar: `compare.title`, `hygiene.title` and `snapshots.title` are
  // the labels of the other workspace tabs, so they belong to navigation ----
  "tabs.aria",
  "tabs.check",
  "compare.title",
  "hygiene.title",
  "hygiene.subtitle",
  "snapshots.title",
  "snapshots.subtitle",

  // ---- check form ----
  "check.panelTitle",
  "check.addressLabel",
  "check.addressPlaceholder",
  "check.servicePortHint",
  "check.portLabel",
  "check.portDefault",
  "check.scenarioLabel",
  "check.modeAll",
  "check.modeUser",
  "check.userSearchPlaceholder",
  "check.groupAll",
  "check.noUsersFound",
  "check.sourceIpLabel",
  "check.sourceIpLoading",
  "check.sourceIpEmpty",
  "check.sourceIpChoose",
  "check.sourceIpActive",
  "check.sourceIpAssigned",
  "check.sourceIpActiveAssigned",
  "check.submit",
  "check.submitAs",
  "check.submitting",
  "check.noRulesWarning",
  "check.orderTitle",
  "check.orderText",
  "check.emptyTitle",
  "check.emptySubtitle",
  "check.resultAllUsers",
  "check.resultAsUser",
  "check.validation.urlRequired",
  "check.validation.userRequired",
  "protocol.any",

  // ---- traffic compare: the form and the three classifications ----
  "compare.subtitle",
  "compare.sideA",
  "compare.sideB",
  "compare.protocolLabel",
  "compare.modeNone",
  "compare.modeUser",
  "compare.modeIp",
  "compare.submit",
  "compare.comparing",
  "compare.empty",
  "compare.classificationSame",
  "compare.classificationDivergent",
  "compare.classificationIncomparable",

  // ---- pipeline stages, statuses and detail labels ----
  "stage.hw_filter",
  "stage.pre_filter",
  "stage.rate_limit",
  "stage.dns",
  "stage.dnat",
  "stage.content_filter",
  "stage.antivirus",
  "stage.firewall",
  "stage.app_control",
  "stage.ips",
  "stage.snat",
  "stage.destination",
  "status.pass",
  "status.block",
  "status.limited",
  "status.resolved",
  "status.active",
  "status.applied",
  "status.conditional",
  "status.skip",
  "status.bypass",
  "status.unknown",
  "status.na",
  "detail.ruleTriggered",
  "detail.action",
  "detail.category",
  "detail.redirect",
  "detail.speedLimit",
  "detail.kbps",
  "detail.limitScope",
  "detail.scopeUser",
  "detail.scopeGroup",
  "detail.hwMode",
  "detail.resolvedIp",
  "detail.firewallTable",
  "detail.translatedDestination",
  "detail.translatedSource",
  "detail.module",
  "detail.moduleOn",
  "detail.moduleOff",
  "detail.noRule",

  // ---- verdict and export ----
  "verdict.allowedTitle",
  "verdict.allowedSub",
  "verdict.blockedTitle",
  "verdict.blockedSubWithRule",
  "verdict.blockedSubNoRule",
  "verdict.conditionalTitle",
  "verdict.conditionalSub",
  "verdict.partialTitle",
  "verdict.partialSub",
  "verdict.unknownTitle",
  "verdict.unknownSub",
  "verdict.categoriesLabel",
  "verdict.targetLabel",
  "verdict.resolvedIpLabel",
  "verdict.sourceIpLabel",
  "verdict.skipAnimation",
  "traceExport.downloadJson",
  "traceExport.print",

  // ---- settings ----
  "settings.title",
  "settings.themeLabel",
  "settings.themeLight",
  "settings.themeDark",
  "settings.themeSystem",
  "settings.accentLabel",
  "settings.languageLabel",
  "settings.storageNote",

  // ---- session ----
  "session.expiredToast",
  "session.loggedOutToast",
  "session.checking",

  // ---- errors: every contract code (docs/API_CONTRACT.md) ----
  "errors.validation_error",
  "errors.invalid_server_address",
  "errors.ngfw_host_not_allowed",
  "errors.invalid_credentials",
  "errors.second_factor_required",
  "errors.second_factor_invalid",
  "errors.second_factor_expired",
  "errors.insufficient_ngfw_permissions",
  "errors.readonly_admin_required",
  "errors.not_authenticated",
  "errors.session_expired",
  "errors.server_unreachable",
  "errors.api_changed",
  "errors.ngfw_error",
  "errors.not_found",
  "errors.internal_error",
  "errors.snapshot_limit_reached",
  "errors.snapshot_import_invalid",
  "errors.snapshot_import_unsupported_format",
  "errors.snapshot_import_too_large",
  "errors.compare_side_invalid",
  "errors.genericTitle",
] as const satisfies readonly MessageKey[];

export type CoreMessageKey = (typeof CORE_MESSAGE_KEYS)[number];

/** A locale that translates everything. */
export type FullDictionary = Record<MessageKey, string>;

/**
 * A locale that translates the core set and may omit the rest. The
 * `Partial<Record<MessageKey, string>>` half is what keeps a typo out: a key
 * that is not a `MessageKey` at all is rejected as an excess property.
 */
export type CoreDictionary = Record<CoreMessageKey, string> & Partial<Record<MessageKey, string>>;

/** Any dictionary, at either tier, as the runtime reads it. */
export type LocaleDictionary = Partial<Record<MessageKey, string>>;
