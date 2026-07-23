"use client";

import { useEffect, useState } from "react";
import { useSession } from "@/contexts/SessionContext";
import { useApiErrorMessage } from "@/hooks/useApiErrorMessage";
import * as api from "@/lib/api";
import { toApiError } from "@/lib/errors";
import { NgfwUser, UserSourceAddress } from "@/lib/types";

export type TraceMode = "all" | "user";

interface Options {
  mode: TraceMode;
  rulesLoaded: boolean;
  usersVersion: number;
}

/** Load the user picker and source addresses required for a user-scoped trace.
 *
 * The selected user's source list is dynamic, whereas the users list belongs to
 * the rules snapshot. A successful rules refresh invalidates both requests.
 * Each effect ignores stale responses so switching mode/user cannot overwrite
 * a newer selection with an earlier response.
 */
export function useTraceSubjects({ mode, rulesLoaded, usersVersion }: Options) {
  const session = useSession();
  const errorMessage = useApiErrorMessage();
  const [users, setUsers] = useState<NgfwUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [usersFetched, setUsersFetched] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [sourceAddresses, setSourceAddresses] = useState<UserSourceAddress[]>([]);
  const [sourceAddressesLoading, setSourceAddressesLoading] = useState(false);
  const [sourceAddressesError, setSourceAddressesError] = useState<string | null>(null);
  const [selectedSourceIp, setSelectedSourceIp] = useState<string | null>(null);

  useEffect(() => {
    if (usersVersion > 0) setUsersFetched(false);
  }, [usersVersion]);

  useEffect(() => {
    if (mode !== "user" || usersFetched || !rulesLoaded) return;
    let cancelled = false;
    setUsersLoading(true);
    setUsersError(null);
    api
      .getUsers()
      .then((response) => {
        if (cancelled) return;
        setUsers(response.users);
        setUsersFetched(true);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const apiError = toApiError(error);
        if (!session.handleAuthError(apiError)) setUsersError(errorMessage(apiError));
      })
      .finally(() => {
        if (!cancelled) setUsersLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // Session/error callbacks are stable provider values; these are the request keys.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, usersFetched, rulesLoaded]);

  useEffect(() => {
    if (mode !== "user" || !selectedUserId) {
      setSourceAddresses([]);
      setSelectedSourceIp(null);
      setSourceAddressesError(null);
      return;
    }
    let cancelled = false;
    setSourceAddresses([]);
    setSelectedSourceIp(null);
    setSourceAddressesLoading(true);
    setSourceAddressesError(null);
    api
      .getUserSourceAddresses(selectedUserId)
      .then((response) => {
        if (cancelled) return;
        setSourceAddresses(response.addresses);
        setSelectedSourceIp(response.addresses.length === 1 ? response.addresses[0]!.ip : null);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const apiError = toApiError(error);
        if (!session.handleAuthError(apiError)) setSourceAddressesError(errorMessage(apiError));
      })
      .finally(() => {
        if (!cancelled) setSourceAddressesLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // The selected user and refreshed snapshot are the source-address cache key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, selectedUserId, usersVersion]);

  return {
    users,
    usersLoading,
    usersError,
    selectedUserId,
    setSelectedUserId,
    selectedUser: users.find((user) => user.id === selectedUserId) ?? null,
    sourceAddresses,
    sourceAddressesLoading,
    sourceAddressesError,
    selectedSourceIp,
    setSelectedSourceIp,
  };
}
