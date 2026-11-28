// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import React, { useEffect, useRef, useState } from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import Translate, { translate } from '@docusaurus/Translate';
import useBaseUrl from '@docusaurus/useBaseUrl';
import { Search as SearchIcon } from 'lucide-react';

type IndexState = 'loading' | 'ready' | 'dev_fallback';

declare global {
  interface Window {
    PagefindUI?: new (opts: {
      element: string;
      bundlePath?: string;
      showSubResults?: boolean;
      showImages?: boolean;
      resetStyles?: boolean;
    }) => unknown;
  }
}

export default function OfflineSearchPage(): React.JSX.Element {
  const [status, setStatus] = useState<IndexState>('loading');
  const containerRef = useRef<HTMLDivElement | null>(null);
  const pagefindCssUrl = useBaseUrl('/pagefind/pagefind-ui.css');
  const pagefindJsUrl = useBaseUrl('/pagefind/pagefind-ui.js');
  const pagefindBundleUrl = useBaseUrl('/pagefind/');
  const docsIndexUrl = useBaseUrl('/docs-index.json');
  const llmsFullUrl = useBaseUrl('/llms-full.txt');

  useEffect(() => {
    let cancelled = false;
    const container = containerRef.current;
    if (container) {
      container.replaceChildren();
    }

    const css = document.createElement('link');
    css.rel = 'stylesheet';
    css.href = pagefindCssUrl;
    document.head.appendChild(css);

    const script = document.createElement('script');
    script.src = pagefindJsUrl;
    script.async = true;
    script.onload = () => {
      if (cancelled) return;
      if (typeof window.PagefindUI === 'function' && containerRef.current) {
        containerRef.current.replaceChildren();
        new window.PagefindUI({
          element: '#grdr-pagefind-search',
          bundlePath: pagefindBundleUrl,
          showSubResults: true,
          showImages: false,
          resetStyles: false,
        });
        setStatus('ready');
      } else {
        setStatus('dev_fallback');
      }
    };
    script.onerror = () => {
      if (!cancelled) setStatus('dev_fallback');
    };
    document.body.appendChild(script);

    return () => {
      cancelled = true;
      css.remove();
      script.remove();
      if (container) {
        container.replaceChildren();
      }
    };
  }, [pagefindBundleUrl, pagefindCssUrl, pagefindJsUrl]);

  return (
    <Layout
      title={translate({ id: 'search.meta.title', message: 'Offline Search' })}
      description={translate({
        id: 'search.meta.description',
        message: 'Client-side Pagefind full-text documentation search',
      })}
    >
      <main className="grdr-search-shell">
        <div className="grdr-kicker">
          <SearchIcon size={14} strokeWidth={2} aria-hidden="true" />
          <span>
            <Translate id="search.hero.kicker">
              Offline Pagefind Search (Zero External Network Requests)
            </Translate>
          </span>
        </div>
        <h1>
          <Translate id="search.hero.title">Search Documentation</Translate>
        </h1>
        <p className="grdr-hero-sub">
          <Translate id="search.hero.subtitle">
            Full-text search runs locally inside your browser using static Pagefind index shards
            built alongside the documentation site.
          </Translate>
        </p>

        <div className="grdr-search-box">
          <div id="grdr-pagefind-search" ref={containerRef} />
          {status === 'dev_fallback' && (
            <p className="grdr-card-desc">
              <Translate id="search.fallback.prefix">
                Pagefind static assets load from compiled builds (pnpm --dir website run build). In
                static or air-gapped bundles you can also inspect
              </Translate>{' '}
              <a href={docsIndexUrl}>docs-index.json</a>{' '}
              <Translate id="search.fallback.or">or</Translate>{' '}
              <a href={llmsFullUrl}>llms-full.txt</a>
              {', '}
              <Translate id="search.fallback.browse">or browse</Translate>{' '}
              <Link to="/docs/product/tutorials/quickstart">
                <Translate id="search.fallback.quickstart">Quickstart</Translate>
              </Link>
              .
            </p>
          )}
        </div>
      </main>
    </Layout>
  );
}
