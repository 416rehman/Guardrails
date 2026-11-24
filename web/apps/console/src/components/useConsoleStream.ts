import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { connectLiveUrl } from "@grdr/api";
import {
  consoleQueryKeys,
  invalidateConsoleStreamEvent,
  type ConsoleStreamEventName,
} from "../queries";

const STREAM_EVENTS: ReadonlyArray<ConsoleStreamEventName> = [
  "session.verdict",
  "approval.decided",
  "policy.changed",
  "inventory.device",
  "uplink.batch",
  "finding.updated",
  "kill_switch.updated",
  "privacy.updated",
];

export function useConsoleStream(
  streamVersion: number,
  onDisconnectedChange: (disconnected: boolean) => void,
) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (streamVersion > 0) {
      void queryClient.invalidateQueries({ queryKey: consoleQueryKeys.all });
    }
    const events = new EventSource(connectLiveUrl());
    events.onopen = () => onDisconnectedChange(false);
    events.onerror = () => onDisconnectedChange(true);

    const listeners = STREAM_EVENTS.map((eventName) => {
      const handler = () => {
        void invalidateConsoleStreamEvent(queryClient, eventName);
      };
      events.addEventListener(eventName, handler);
      return { eventName, handler };
    });

    return () => {
      for (const { eventName, handler } of listeners) {
        events.removeEventListener?.(eventName, handler);
      }
      events.close();
    };
  }, [queryClient, onDisconnectedChange, streamVersion]);
}
