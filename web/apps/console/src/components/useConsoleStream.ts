import { useEffect } from "react";
import { getApiToken } from "@grdr/api";

export function useConsoleStream(
  streamVersion: number,
  onRefresh: () => Promise<void>,
  onDisconnectedChange: (disconnected: boolean) => void,
) {
  useEffect(() => {
    void onRefresh();
    const token = getApiToken();
    const liveUrl = token
      ? `/api/v1/live?access_token=${encodeURIComponent(token)}`
      : "/api/v1/live";
    const events = new EventSource(liveUrl);
    const refreshHandler = () => {
      void onRefresh();
    };
    events.onopen = () => onDisconnectedChange(false);
    events.onerror = () => onDisconnectedChange(true);
    events.addEventListener("session.verdict", refreshHandler);
    events.addEventListener("approval.decided", refreshHandler);
    events.addEventListener("policy.changed", refreshHandler);
    events.addEventListener("inventory.device", refreshHandler);
    events.addEventListener("uplink.batch", refreshHandler);
    events.addEventListener("finding.updated", refreshHandler);
    events.addEventListener("kill_switch.updated", refreshHandler);
    events.addEventListener("privacy.updated", refreshHandler);
    return () => events.close();
  }, [onRefresh, onDisconnectedChange, streamVersion]);
}
