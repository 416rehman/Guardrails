# ADR-0007: The canonical model is protobuf `v1alpha1` with a `data_class` on every field

- Status: proposed
- Date: 2026-11-11
- Decided by: chief architect
- Spine: D-06, D-51, P8
- Requires: nothing
- RFC: not required while packages are `v1alpha1`; required for any change after the freeze
- Work items: [WI-0014]

## Context
The event model is the contract between sensors, server, lake and exports. Privacy by schema (P8) works only if every field states what kind of data it holds, so the capture level can be applied as a filter on the device (briefs 23, 26, 34; reviews c1, l07).

## Decision
The canonical model is our own protobuf under `proto/grdr/**`, packages `grdr.*.v1alpha1`, frozen before the server's first release. Every field carries a `data_class` option: identifier, structural, derived or content. OCSF is a generated export and OTel GenAI, OpenInference and OpenLLMetry are ingest dialects, never the model.

## Enforced by
`buf lint` and `buf breaking` in `verify` and CI; `grdr-schema-lint`, which fails a field with no `data_class`; the `rfc-required` check on `proto/**`.

## Consequences
The capture level, redaction and export mappings are generated from field options. Adding a field without classifying it does not build.

## Alternatives rejected
- OCSF as the canonical model: it moves under us and has no data classes.
- Classification in a side file: it drifts from the fields it describes.

## Revisit when
The packages freeze: a later record states the stable package names and the overlap rule of D-60.
