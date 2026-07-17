import { ErrorCode, KNOWN_ERROR_CODES } from "./types";

/**
 * Thrown by everything in lib/api.ts. Carries the contract error code (§2 of
 * API_CONTRACT.md) so the UI can render a localized, human-readable message
 * instead of ever showing a raw stack trace or JSON blob.
 */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly httpStatus: number | null;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, opts?: { httpStatus?: number; details?: Record<string, unknown> }) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.httpStatus = opts?.httpStatus ?? null;
    this.details = opts?.details;
  }
}

/** Contract §5.4: unknown codes must not crash the UI — fall back to a generic code. */
export function normalizeErrorCode(code: string | undefined | null): ErrorCode {
  if (code && (KNOWN_ERROR_CODES as readonly string[]).includes(code)) {
    return code as ErrorCode;
  }
  return "ngfw_error";
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

/**
 * Central debug logging for API failures (Phase 2.5). Single format, easy to
 * grep in the browser console. Deliberately logs ONLY the error code, the
 * endpoint path and the HTTP status — never request bodies (they may contain
 * the admin password), never cookies, never backend `message`/`details`
 * (surfaced in the UI where relevant instead). Console-only: nothing is sent
 * anywhere (no telemetry).
 */
export function logApiError(endpoint: string, err: ApiError): void {
  // eslint-disable-next-line no-console
  console.error(`[stuck] api error: code=${err.code} endpoint=${endpoint} status=${err.httpStatus ?? "-"}`);
}

/** Best-effort conversion of any thrown value into an ApiError, for use at UI boundaries. */
export function toApiError(err: unknown): ApiError {
  if (isApiError(err)) return err;
  if (err instanceof Error) {
    return new ApiError("internal_error", err.message);
  }
  return new ApiError("internal_error", String(err));
}
