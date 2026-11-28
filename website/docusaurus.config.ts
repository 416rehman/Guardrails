// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Guardrails ADR',
  tagline: 'Open-source Agent Detection and Response at tool boundaries',
  url: 'https://docs.guardrailshq.com',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  staticDirectories: ['static'],
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'ar'],
    localeConfigs: {
      en: {
        label: 'English',
        direction: 'ltr',
        htmlLang: 'en-US',
      },
      ar: {
        label: 'Arabic (RTL)',
        direction: 'rtl',
        htmlLang: 'ar',
      },
    },
  },
  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          include: [
            'product/**',
            'runbooks/**',
            'extending/**',
            'training/**',
            'crates/**',
            'community/**',
          ],
          exclude: [],
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],
  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Guardrails ADR',
      items: [
        {
          to: '/docs/product/tutorials/quickstart',
          label: 'Documentation',
          position: 'left',
        },
        {
          to: '/docs/runbooks/rb-index',
          label: 'Runbooks',
          position: 'left',
        },
        {
          to: '/docs/extending/',
          label: 'Extending',
          position: 'left',
        },
        {
          to: '/search',
          label: 'Search',
          position: 'right',
        },
        {
          href: 'pathname:///llms.txt',
          label: 'llms.txt',
          position: 'right',
        },
        {
          type: 'localeDropdown',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'light',
      links: [
        {
          title: 'Guides',
          items: [
            { label: 'Quickstart', to: '/docs/product/tutorials/quickstart' },
            { label: 'Configure Hooks & MCP', to: '/docs/product/how-to/configure-hooks-and-mcp' },
            { label: 'Server Storage Profiles', to: '/docs/product/operate/server-profiles' },
          ],
        },
        {
          title: 'Operations',
          items: [
            { label: 'Runbook Index (RB-01..12)', to: '/docs/runbooks/rb-index' },
            { label: 'Fleet Verification Checklist', to: '/docs/runbooks/FLEET-VERIFY' },
            { label: 'Hosted SaaS Cells', to: '/docs/product/operate/saas-cells' },
          ],
        },
        {
          title: 'Contracts & Offline Corpus',
          items: [
            { label: 'Registered Error Codes', to: '/docs/product/reference/_generated/ref-error-codes' },
            { label: 'Workspace Crate Layers', to: '/docs/product/reference/_generated/ref-crate-layers' },
            { label: 'Full Offline Index (JSON)', href: 'pathname:///docs-index.json' },
          ],
        },
      ],
      copyright: 'Apache-2.0 / CC-BY-4.0 | The Guardrails ADR Authors',
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
