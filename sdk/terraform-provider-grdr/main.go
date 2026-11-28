// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/416rehman/Guardrails/sdk/go/grdr"
	"github.com/416rehman/Guardrails/sdk/terraform-provider-grdr/provider"
)

func main() {
	schemaFlag := flag.Bool("schema", false, "Print provider resource and data-source schema as JSON")
	flag.Parse()

	endpoint := os.Getenv("GRDR_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8787"
	}
	token := os.Getenv("GRDR_TOKEN")
	prov := provider.NewProvider(grdr.NewClient(grdr.ClientOptions{
		BaseURL:   endpoint,
		Token:     token,
		UserAgent: "terraform-provider-grdr/0.1.0",
	}))

	if *schemaFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(prov.SchemaDocument()); err != nil {
			fmt.Fprintf(os.Stderr, "encode schema: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintf(
		os.Stdout,
		"terraform-provider-grdr ready (%d resources, %d data sources)\n",
		len(prov.ResourceTypes()),
		len(prov.DataSourceTypes()),
	)
}
