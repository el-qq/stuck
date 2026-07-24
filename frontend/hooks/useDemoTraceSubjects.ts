"use client";

import { useEffect, useMemo, useState } from "react";
import type { TraceMode, TraceSubjectsState } from "./useTraceSubjects";
import { DEMO_SOURCE_ADDRESSES, DEMO_USERS } from "@/lib/demoData";

/**
 * Offline adapter for `TraceSubjectsState`: no API/session imports, all
 * users and source addresses are static fixtures. Shared by the check tab
 * and each side of the access-compare tab's demo adapter.
 */
export function useDemoTraceSubjects(mode: TraceMode, initialUserId: string | null = null): TraceSubjectsState {
  const [selectedUserId, setSelectedUserId] = useState<string | null>(initialUserId);
  const [selectedSourceIp, setSelectedSourceIp] = useState<string | null>(null);
  const selectedUser = DEMO_USERS.find((user) => user.id === selectedUserId) ?? null;
  const sourceAddresses = useMemo(() => (selectedUser ? (DEMO_SOURCE_ADDRESSES[selectedUser.id] ?? []) : []), [selectedUser]);

  useEffect(() => {
    if (mode !== "user" || sourceAddresses.length !== 1) {
      setSelectedSourceIp(null);
      return;
    }
    setSelectedSourceIp(sourceAddresses[0]!.ip);
  }, [mode, selectedUserId, sourceAddresses]);

  return {
    users: DEMO_USERS,
    usersLoading: false,
    usersError: null,
    selectedUserId,
    setSelectedUserId,
    selectedUser,
    sourceAddresses,
    sourceAddressesLoading: false,
    sourceAddressesError: null,
    selectedSourceIp,
    setSelectedSourceIp,
  };
}
