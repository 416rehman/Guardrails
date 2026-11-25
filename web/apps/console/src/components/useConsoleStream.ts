import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { fetchLiveEventsUrl } from "@grdr/api";
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
    let active = true;
    let events: EventSource | null = null;
    const listeners: Array<{ eventName: ConsoleStreamEventName; handler: () => void }> = [];

    void fetchLiveEventsUrl()
      .then((url) => {
        if (!active) return;
        events = new EventSource(url);
        events.onopen = () => onDisconnectedChange(false);
        events.onerror = () => onDisconnectedChange(true);
        for (const eventName of STREAM_EVENTS) {
          const handler = () => {
            void invalidateConsoleStreamEvent(queryClient, eventName);
          };
          events.addEventListener(eventName, handler);
          listeners.push({ eventName, handler });
        }
      })
      .catch(() => {
        if (active) onDisconnectedChange(true);
      });

    return () => {
      active = false;
      if (events) {
        for (const { eventName, handler } of listeners) {
          events.removeEventListener?.(eventName, handler);
        }
        events.close();
      }
    };
  }, [queryClient, onDisconnectedChange, streamVersion]);
}
