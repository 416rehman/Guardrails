// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import Translate, { translate } from '@docusaurus/Translate';
import {
  ArrowRight,
  BookOpen,
  Blocks,
  FileCode2,
  Search,
  Server,
  ShieldCheck,
  Terminal,
} from 'lucide-react';

interface TrackCard {
  id: string;
  title: string;
  description: string;
  to: string;
  Icon: React.ComponentType<{ size?: number; strokeWidth?: number }>;
}

const TRACKS: TrackCard[] = [
  {
    id: 'quickstart',
    title: translate({
      id: 'home.track.quickstart.title',
      message: 'Quickstart Tutorial',
    }),
    description: translate({
      id: 'home.track.quickstart.desc',
      message: 'Run split Console and Operator planes, daemon IPC self-test, and hook checks locally.',
    }),
    to: '/docs/product/tutorials/quickstart',
    Icon: Terminal,
  },
  {
    id: 'hooks',
    title: translate({
      id: 'home.track.hooks.title',
      message: 'Hooks & MCP Proxy',
    }),
    description: translate({
      id: 'home.track.hooks.desc',
      message: 'Install reversible agent hooks and inspect stdio JSON-RPC MCP tool calls offline.',
    }),
    to: '/docs/product/how-to/configure-hooks-and-mcp',
    Icon: ShieldCheck,
  },
  {
    id: 'cells',
    title: translate({
      id: 'home.track.cells.title',
      message: 'Storage Profiles & Cells',
    }),
    description: translate({
      id: 'home.track.cells.desc',
      message:
        'Operate embedded SQLite, HA PostgreSQL 18, distributed NATS JetStream, and 4096-bucket cells.',
    }),
    to: '/docs/product/operate/saas-cells',
    Icon: Server,
  },
  {
    id: 'runbooks',
    title: translate({
      id: 'home.track.runbooks.title',
      message: 'Incident Runbooks (RB-01..12)',
    }),
    description: translate({
      id: 'home.track.runbooks.desc',
      message: 'Structured DR restore under 4h RTO, key rotation, reconciliation halt, and burn-rate triage.',
    }),
    to: '/docs/runbooks/rb-index',
    Icon: BookOpen,
  },
  {
    id: 'extending',
    title: translate({
      id: 'home.track.extending.title',
      message: 'Extending Guardrails',
    }),
    description: translate({
      id: 'home.track.extending.desc',
      message: 'Add agent manifests, Cedar policy packs, and grdr-ports adapters without core forks.',
    }),
    to: '/docs/extending/',
    Icon: Blocks,
  },
  {
    id: 'contracts',
    title: translate({
      id: 'home.track.contracts.title',
      message: 'Generated Contract Reference',
    }),
    description: translate({
      id: 'home.track.contracts.desc',
      message: 'Machine-verified tables of registered GRDR error codes, crate layers, and support bounds.',
    }),
    to: '/docs/product/reference/_generated/ref-error-codes',
    Icon: FileCode2,
  },
];

export default function Home(): React.JSX.Element {
  return (
    <Layout
      title={translate({ id: 'home.meta.title', message: 'Documentation' })}
      description={translate({
        id: 'home.meta.description',
        message: 'Guardrails ADR official documentation, runbooks, and architecture contracts',
      })}
    >
      <header className="grdr-hero">
        <div className="grdr-hero-inner">
          <div className="grdr-kicker">
            <ShieldCheck size={14} strokeWidth={2} aria-hidden="true" />
            <span>
              <Translate id="home.hero.kicker">
                grdr v0.1 | Split Control Planes | OS Peer IPC
              </Translate>
            </span>
          </div>
          <h1 className="grdr-hero-title">
            <Translate id="home.hero.title">Guardrails ADR Documentation</Translate>
          </h1>
          <p className="grdr-hero-sub">
            <Translate id="home.hero.subtitle">
              Discover AI coding agents and MCP servers dynamically, enforce Cedar policies and
              signed binary floor packs locally, and operate air-gapped or multi-cell deployments
              without third-party runtime dependencies.
            </Translate>
          </p>
          <div className="grdr-actions">
            <Link className="grdr-btn-primary" to="/docs/product/tutorials/quickstart">
              <span>
                <Translate id="home.cta.quickstart">Start Quickstart</Translate>
              </span>
              <ArrowRight size={16} strokeWidth={2} aria-hidden="true" />
            </Link>
            <Link className="grdr-btn-secondary" to="/search">
              <Search size={16} strokeWidth={2} aria-hidden="true" />
              <span>
                <Translate id="home.cta.search">Search Offline Docs</Translate>
              </span>
            </Link>
            <Link className="grdr-btn-secondary" to="/docs/runbooks/rb-index">
              <span>
                <Translate id="home.cta.runbooks">Runbooks</Translate>
              </span>
            </Link>
          </div>
          <div className="grdr-command-strip">
            <div className="grdr-command-label">
              <Translate id="home.command.label">
                Split Console + Operator server &amp; OS peer IPC self-test
              </Translate>
            </div>
            <code className="grdr-command-code">
              {[
                'cargo run -p grdr-server -- --bind 127.0.0.1:8787 --operator-bind 127.0.0.1:8788 --web-dir web/dist --operator-web-dir web/dist-operator --demo-seed --data-dir ./grdr-data',
                'cargo run -p grdr-daemon -- --self-test',
              ].join('\n')}
            </code>
          </div>
        </div>
      </header>

      <main className="grdr-grid-section">
        <div className="grdr-grid">
          {TRACKS.map(({ id, title, description, to, Icon }) => (
            <Link key={id} className="grdr-card" to={to}>
              <div className="grdr-card-head">
                <Icon size={18} strokeWidth={1.8} aria-hidden="true" />
                <span>{title}</span>
              </div>
              <p className="grdr-card-desc">{description}</p>
            </Link>
          ))}
        </div>
      </main>
    </Layout>
  );
}
