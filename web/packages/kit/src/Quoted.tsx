// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { t } from "@grdr/i18n";
import { GrdrIcon, useGrdrLocale } from "@grdr/ui";

const BENIGN_WHITESPACE_REGEX = /[\t\n\r]+/g;
const BIDI_OR_CONTROL_REGEX =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u061C\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

export function sanitizeUntrustedText(text: string): { safeText: string; stripped: boolean } {
  let stripped = false;
  const normalized = text.replace(BENIGN_WHITESPACE_REGEX, " ");
  const safeText = normalized.replace(BIDI_OR_CONTROL_REGEX, () => {
    stripped = true;
    return "";
  });
  return { safeText, stripped };
}

export function Quoted({ text }: { text: string }) {
  const { locale } = useGrdrLocale();
  const { safeText, stripped } = sanitizeUntrustedText(text);
  const warningLabel = stripped ? t("kit.quoted.bidi_flagged", undefined, locale) : undefined;
  const badgeLabel = stripped ? t("kit.quoted.bidi_badge", undefined, locale) : undefined;
  return (
    <span className="grdr-ui-quoted" title={warningLabel}>
      <bdi dir="ltr">{safeText}</bdi>
      {stripped && (
        <span
          role="status"
          aria-label={warningLabel}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            fontSize: 11,
            color: "var(--tone-ask)",
            marginInlineStart: 6,
          }}
        >
          <GrdrIcon name="alert-triangle" size={12} />
          <span>{badgeLabel}</span>
        </span>
      )}
    </span>
  );
}
