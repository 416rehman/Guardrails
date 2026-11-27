// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import { useState } from "react";
import type { LegalHoldEntry, SubjectRequestEntry } from "@grdr/api";
import { capitalizeLabel } from "@grdr/i18n";
import { Quoted } from "@grdr/kit";
import {
  Badge,
  Banner,
  Button,
  Card,
  EmptyState,
  GrdrIcon,
  Heading,
  HStack,
  StatusInline,
  Text,
  TextInput,
  UiSdkSegmentedControl,
  VStack,
} from "@grdr/ui";

type DsarKind = "access" | "erasure" | "restriction" | "objection";

type DsarSubmissionState =
  | { kind: "idle" }
  | { kind: "submitted"; requestKind: DsarKind; subjectRef: string; heldByHoldIds: string[] };

interface ComplianceGovernanceSectionProps {
  matterRef: string;
  onChangeMatterRef: (v: string) => void;
  holdTarget: string;
  onChangeHoldTarget: (v: string) => void;
  holdReason: string;
  onChangeHoldReason: (v: string) => void;
  busy: boolean;
  legalHolds: LegalHoldEntry[];
  subjectRequests: SubjectRequestEntry[];
  onSubmitHold: () => void;
  onCosignHold: (holdId: string) => void;
}

function shellQuote(raw: string): string {
  return `'${raw.replace(/'/g, "'\\''")}'`;
}

export function ComplianceGovernanceSection({
  matterRef,
  onChangeMatterRef,
  holdTarget,
  onChangeHoldTarget,
  holdReason,
  onChangeHoldReason,
  busy,
  legalHolds,
  subjectRequests,
  onSubmitHold,
  onCosignHold,
}: ComplianceGovernanceSectionProps) {
  const [dsarKind, setDsarKind] = useState<DsarKind>("erasure");
  const [customSubject, setCustomSubject] = useState<string | null>(null);
  const [dsarState, setDsarState] = useState<DsarSubmissionState>({ kind: "idle" });

  const dsarSubject =
    customSubject ?? subjectRequests[0]?.subject_ref ?? legalHolds[0]?.scope_summary ?? "";

  const matchingActiveHolds = legalHolds.filter(
    (h) =>
      h.lifecycle === "active" &&
      dsarSubject.trim().length > 0 &&
      h.scope_summary.toLowerCase().includes(dsarSubject.trim().toLowerCase()),
  );

  function handleStageDsar() {
    const cleanSubject = dsarSubject.trim();
    if (!cleanSubject) return;
    setDsarState({
      kind: "submitted",
      requestKind: dsarKind,
      subjectRef: cleanSubject,
      heldByHoldIds: matchingActiveHolds.map((h) => h.hold_id),
    });
  }

  return (
    <div className="grid-2">
      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <Heading level={2}>Legal holds ledger</Heading>
            <Badge variant="warning" label="Two-approver quorum" />
          </HStack>
          <div className="grid-2">
            <TextInput label="Matter reference" value={matterRef} onChange={onChangeMatterRef} />
            <TextInput
              label="Pseudonym or session"
              placeholder="Enter pseudonym or scope ref"
              value={holdTarget}
              onChange={onChangeHoldTarget}
            />
          </div>
          <TextInput label="Preservation rationale" value={holdReason} onChange={onChangeHoldReason} />
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <Text size="sm" color="secondary">
              Submitting starts 1/2 quorum under your signed-in session. A second principal co-signs to activate.
            </Text>
            <Button
              variant="primary"
              size="sm"
              label="Place legal hold (1/2)"
              isDisabled={busy || matterRef.trim() === "" || holdTarget.trim() === ""}
              onClick={onSubmitHold}
            />
          </HStack>
          {legalHolds.length === 0 ? (
            <EmptyState
              title="No active legal holds"
              description="Stage a two-approver preservation hold above to pin decision and audit records against scheduled retention deletion."
              icon={<GrdrIcon name="lock" size={20} />}
            />
          ) : (
            <div className="checklist">
              {legalHolds.map((h) => (
                <div key={h.hold_id} className="check-row" style={{ flexWrap: "wrap", gap: 8 }}>
                  <VStack gap={0}>
                    <Text size="sm" weight="semibold">
                      {h.matter_ref}
                    </Text>
                    <Quoted text={h.scope_summary} />
                    <Text size="sm" color="secondary">
                      {`Approvers (${h.approvers.length}/2): ${h.approvers.join(", ")}`}
                    </Text>
                  </VStack>
                  <HStack gap={2} align="center">
                    <StatusInline
                      tone={h.lifecycle === "active" ? "allow" : "ask"}
                      dot
                      label={capitalizeLabel(h.lifecycle.replace(/_/g, " "))}
                    />
                    {h.lifecycle === "pending_quorum" && (
                      <Button
                        variant="secondary"
                        size="sm"
                        label="Co-sign hold (quorum)"
                        isDisabled={busy}
                        onClick={() => onCosignHold(h.hold_id)}
                      />
                    )}
                  </HStack>
                </div>
              ))}
            </div>
          )}
        </VStack>
      </Card>

      <Card padding={3}>
        <VStack gap={3}>
          <HStack justify="between" align="center" style={{ flexWrap: "wrap", gap: 8 }}>
            <Heading level={2}>Subject access & erasure requests</Heading>
            <Badge variant="neutral" label={`${subjectRequests.length} recorded`} />
          </HStack>

          <VStack gap={2}>
            <UiSdkSegmentedControl<DsarKind>
              ariaLabel="Subject request kind"
              value={dsarKind}
              onChange={(next) => {
                setDsarKind(next);
                setDsarState({ kind: "idle" });
              }}
              options={[
                { value: "erasure", label: "Erasure" },
                { value: "access", label: "Access" },
                { value: "restriction", label: "Restrict" },
                { value: "objection", label: "Object" },
              ]}
            />
            <HStack gap={2} align="end" style={{ flexWrap: "wrap" }}>
              <div style={{ flex: "1 1 200px", minWidth: 0 }}>
                <TextInput
                  label="Subject pseudonym or directory reference"
                  placeholder="Enter subject pseudonym or directory ref"
                  value={dsarSubject}
                  onChange={(val) => {
                    setCustomSubject(val);
                    setDsarState({ kind: "idle" });
                  }}
                  width="100%"
                />
              </div>
              <Button
                variant="secondary"
                size="sm"
                label={`Stage ${dsarKind} request`}
                isDisabled={busy || dsarSubject.trim() === ""}
                onClick={handleStageDsar}
              />
            </HStack>
            {dsarKind === "erasure" && matchingActiveHolds.length > 0 && (
              <Banner
                status="warning"
                title={`Active legal hold pins ${dsarSubject.trim()}`}
                description="Erasure requests targeting an active legal hold remain in pending held status until dual-approver release."
                collapsible={false}
              />
            )}
            {dsarState.kind === "submitted" && (
              <Banner
                status="info"
                title={`Host CLI required for ${dsarState.requestKind} request (${dsarState.subjectRef})`}
                description={
                  dsarState.heldByHoldIds.length > 0
                    ? `Active holds (${dsarState.heldByHoldIds.join(", ")}) block deletion. Apply via host CLI: grdr comply dsr create --kind ${shellQuote(dsarState.requestKind)} --subject ${shellQuote(dsarState.subjectRef)}`
                    : `Apply via host CLI on the server: grdr comply dsr create --kind ${shellQuote(dsarState.requestKind)} --subject ${shellQuote(dsarState.subjectRef)}`
                }
                collapsible={false}
              />
            )}
          </VStack>

          {subjectRequests.length === 0 ? (
            <EmptyState
              title="No subject access or erasure requests"
              description="Stage an access, erasure, or restriction request above to prepare the host CLI command."
              icon={<GrdrIcon name="file-text" size={20} />}
            />
          ) : (
            <div className="table-wrap">
              <table className="table responsive-table">
                <thead>
                  <tr>
                    <th>Request</th>
                    <th>Kind</th>
                    <th>Subject ref</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {subjectRequests.map((sr) => (
                    <tr key={sr.request_id}>
                      <td data-label="Request" className="mono">
                        {sr.request_id}
                      </td>
                      <td data-label="Kind">{capitalizeLabel(sr.kind)}</td>
                      <td data-label="Subject ref" className="mono">
                        {sr.subject_ref}
                      </td>
                      <td data-label="Status">
                        <StatusInline
                          tone={sr.status === "pending_held" ? "ask" : "allow"}
                          dot
                          label={sr.status === "pending_held" ? "Held by legal hold" : "Executed"}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </VStack>
      </Card>
    </div>
  );
}
