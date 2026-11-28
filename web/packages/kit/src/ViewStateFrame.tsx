// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { ReactNode } from "react";
import { t } from "@grdr/i18n";
import { Banner, EmptyState, useGrdrLocale } from "@grdr/ui";

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
  const { locale } = useGrdrLocale();

  if (state === "empty") {
    return (
      <EmptyState
        title={title ?? t("kit.view_state.empty", undefined, locale)}
        description={description}
        actions={actions}
      />
    );
  }

  if (state === "error" || state === "unreachable") {
    return (
      <Banner
        status="error"
        title={title ?? t("kit.view_state.error", undefined, locale)}
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
          title={title ?? t("kit.view_state.read_only", undefined, locale)}
          description={description}
        />
        {children}
      </>
    );
  }

  return <>{children}</>;
}
