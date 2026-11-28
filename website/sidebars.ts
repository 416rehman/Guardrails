// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Tutorials',
      items: ['product/tutorials/quickstart'],
    },
    {
      type: 'category',
      label: 'How-To Guides',
      items: [
        'product/how-to/configure-hooks-and-mcp',
        'product/how-to/manage-packs-and-cedar',
      ],
    },
    {
      type: 'category',
      label: 'Architecture & Concepts',
      items: [
        'product/concepts/architecture-and-trust',
        'product/embed/port-contracts',
        'product/lifecycle/releases-and-upgrades',
      ],
    },
    {
      type: 'category',
      label: 'Operate',
      items: [
        'product/operate/server-profiles',
        'product/operate/saas-cells',
        'product/operate/support-bundles-and-verify',
      ],
    },
    {
      type: 'category',
      label: 'Reference (Generated)',
      items: [
        'product/reference/_generated/ref-error-codes',
        'product/reference/_generated/ref-crate-layers',
        'product/reference/_generated/ref-surfaces-and-support',
      ],
    },
    {
      type: 'category',
      label: 'Runbooks & Fleet Verification',
      items: [
        'runbooks/rb-index',
        'runbooks/FLEET-VERIFY',
        'runbooks/RB-01',
        'runbooks/RB-02',
        'runbooks/RB-03',
        'runbooks/RB-04',
        'runbooks/RB-05',
        'runbooks/RB-06',
        'runbooks/RB-07',
        'runbooks/RB-08',
        'runbooks/RB-09',
        'runbooks/RB-10',
        'runbooks/RB-11',
        'runbooks/RB-12',
      ],
    },
    {
      type: 'category',
      label: 'Extending & Training',
      items: [
        'extending/README',
        'extending/adding-an-agent-manifest',
        'extending/adding-a-rule-or-pack',
        'extending/adding-a-port-adapter',
        'crates/README',
        'training/README',
        'training/developer-lab',
        'training/operator-lab',
        'community/health',
      ],
    },
  ],
};

export default sidebars;
