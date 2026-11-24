import type { ReactNode } from "react";
import { Banner, EmptyState } from "@grdr/ui";

export type ViewStateKind =
  | "ready"
  | "empty"
  | "error"
  | "unreachable"
  | "stale"
  | "read-only";

export function ViewStateFrame({
  state,
  title,
  description,
  actions,
  children,
}: {
  state: ViewStateKind;
  title?: string;
  description?: string;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  if (state === "empty") {
    return (
      <EmptyState
        title={title ?? "Nothing recorded yet"}
        description={description}
        actions={actions}
      />
    );
  }

  if (state === "error" || state === "unreachable") {
    return (
      <Banner
        status="error"
        title={title ?? "Connection failed"}
        description={description}
        role="alert"
      />
    );
  }

  if (state === "stale" || state === "read-only") {
    return (
      <>
        <Banner
          status="warning"
          title={title ?? "Read-only view"}
          description={description}
        />
        {children}
      </>
    );
  }

  return <>{children}</>;
}
