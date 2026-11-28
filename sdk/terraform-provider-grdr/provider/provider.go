// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"

	"github.com/416rehman/Guardrails/sdk/go/grdr"
)

var (
	ErrUnknownResource           = errors.New("unknown Terraform resource type")
	ErrUnknownDataSource         = errors.New("unknown Terraform data source")
	ErrWideningPendingApproval   = errors.New("policy change introduces widening and requires human approval before Terraform apply can complete")
	ErrPolicyChangeFailedOrDenied = errors.New("policy change entered terminal failure or denied state")
	ErrOperatorClientRequired    = errors.New("grdr_operator_setting requires an isolated operator plane client (D-70)")
)

type ResourceSpec struct {
	TypeName     string
	Endpoint     string
	ItemsKey     string
	OperatorOnly bool
	Sensitive    []string
	ServerFields []string
}

type DataSourceSpec struct {
	TypeName string
	Endpoint string
}

type Provider struct {
	client         *grdr.Client
	operatorClient *grdr.Client
	resources      map[string]ResourceSpec
	dataSources    map[string]DataSourceSpec
}

type PlanAction string

const (
	PlanNoOp    PlanAction = "no-op"
	PlanCreate  PlanAction = "create"
	PlanUpdate  PlanAction = "update"
	PlanDestroy PlanAction = "destroy"
)

type ResourcePlan struct {
	Action        PlanAction
	ChangedFields []string
}

func NewProvider(client *grdr.Client) *Provider {
	p := &Provider{
		client:      client,
		resources:   make(map[string]ResourceSpec),
		dataSources: make(map[string]DataSourceSpec),
	}
	for _, spec := range defaultResourceSpecs() {
		p.resources[spec.TypeName] = spec
	}
	for _, ds := range defaultDataSourceSpecs() {
		p.dataSources[ds.TypeName] = ds
	}
	return p
}

func (p *Provider) ResourceTypes() []string {
	out := make([]string, 0, len(p.resources))
	for k := range p.resources {
		out = append(out, k)
	}
	return out
}

func (p *Provider) DataSourceTypes() []string {
	out := make([]string, 0, len(p.dataSources))
	for k := range p.dataSources {
		out = append(out, k)
	}
	return out
}

func (p *Provider) SchemaDocument() map[string]any {
	res := make(map[string]any, len(p.resources))
	for name, spec := range p.resources {
		res[name] = map[string]any{
			"endpoint":  spec.Endpoint,
			"sensitive": spec.Sensitive,
		}
	}
	ds := make(map[string]any, len(p.dataSources))
	for name, spec := range p.dataSources {
		ds[name] = map[string]any{"endpoint": spec.Endpoint}
	}
	return map[string]any{
		"schema":       "grdr.terraform-provider.v1alpha1",
		"resources":    res,
		"data_sources": ds,
	}
}

func (p *Provider) Plan(typeName string, prior map[string]any, desired map[string]any) (ResourcePlan, error) {
	spec, ok := p.resources[typeName]
	if !ok {
		return ResourcePlan{}, fmt.Errorf("%w: %s", ErrUnknownResource, typeName)
	}
	if desired == nil && prior != nil {
		return ResourcePlan{Action: PlanDestroy}, nil
	}
	if prior == nil {
		return ResourcePlan{Action: PlanCreate, ChangedFields: sortedKeys(desired)}, nil
	}
	ignore := make(map[string]struct{}, len(spec.ServerFields)+1)
	ignore["id"] = struct{}{}
	for _, f := range spec.ServerFields {
		ignore[f] = struct{}{}
	}
	var changed []string
	for k, v := range desired {
		if _, skip := ignore[k]; skip {
			continue
		}
		if !reflect.DeepEqual(prior[k], v) {
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 {
		return ResourcePlan{Action: PlanNoOp}, nil
	}
	return ResourcePlan{Action: PlanUpdate, ChangedFields: changed}, nil
}

func (p *Provider) SetOperatorClient(client *grdr.Client) {
	p.operatorClient = client
}

func (p *Provider) clientForSpec(spec ResourceSpec) (*grdr.Client, error) {
	if spec.OperatorOnly {
		if p.operatorClient == nil {
			return nil, ErrOperatorClientRequired
		}
		return p.operatorClient, nil
	}
	return p.client, nil
}

func (p *Provider) ApplyCreate(ctx context.Context, typeName string, attrs map[string]any) (map[string]any, error) {
	if typeName == "grdr_policy_source" {
		return p.applyPolicySource(ctx, "", attrs)
	}
	if typeName == "grdr_gitops_binding" {
		return p.client.UpsertGitopsBinding(ctx, attrs)
	}
	spec, ok := p.resources[typeName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownResource, typeName)
	}
	client, err := p.clientForSpec(spec)
	if err != nil {
		return nil, err
	}
	out, err := client.Mutate(ctx, "POST", spec.Endpoint, attrs, "")
	if err != nil {
		return out, err
	}
	if err := checkTerminalResourceState(out); err != nil {
		return out, err
	}
	return out, nil
}

func (p *Provider) Read(ctx context.Context, typeName string, id string) (map[string]any, error) {
	if typeName == "grdr_gitops_binding" {
		return p.client.GetGitopsBinding(ctx)
	}
	spec, ok := p.resources[typeName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownResource, typeName)
	}
	client, err := p.clientForSpec(spec)
	if err != nil {
		return nil, err
	}
	return client.Get(ctx, spec.Endpoint+"/"+url.PathEscape(id))
}

func (p *Provider) ApplyUpdate(ctx context.Context, typeName string, id string, attrs map[string]any) (map[string]any, error) {
	if typeName == "grdr_policy_source" {
		return p.applyPolicySource(ctx, id, attrs)
	}
	if typeName == "grdr_gitops_binding" {
		return p.client.UpsertGitopsBinding(ctx, attrs)
	}
	spec, ok := p.resources[typeName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownResource, typeName)
	}
	client, err := p.clientForSpec(spec)
	if err != nil {
		return nil, err
	}
	out, err := client.Mutate(ctx, "PUT", spec.Endpoint+"/"+url.PathEscape(id), attrs, "")
	if err != nil {
		return out, err
	}
	if err := checkTerminalResourceState(out); err != nil {
		return out, err
	}
	return out, nil
}

func (p *Provider) ApplyDelete(ctx context.Context, typeName string, id string) error {
	spec, ok := p.resources[typeName]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownResource, typeName)
	}
	client, err := p.clientForSpec(spec)
	if err != nil {
		return err
	}
	path := spec.Endpoint
	if typeName != "grdr_gitops_binding" && id != "" {
		path = path + "/" + url.PathEscape(id)
	}
	_, err = client.Mutate(ctx, "DELETE", path, map[string]any{}, "")
	return err
}

func checkTerminalResourceState(doc map[string]any) error {
	state, _ := doc["state"].(string)
	if state == "FAILED" || state == "DENIED" || state == "ROLLED_BACK" {
		return fmt.Errorf("%w: state=%s", ErrPolicyChangeFailedOrDenied, state)
	}
	return nil
}

func (p *Provider) ReadDataSource(ctx context.Context, typeName string) (map[string]any, error) {
	ds, ok := p.dataSources[typeName]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDataSource, typeName)
	}
	return p.client.Get(ctx, ds.Endpoint)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
