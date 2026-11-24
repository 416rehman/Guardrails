import { useCallback, useEffect, useState } from "react";
import type { PageInfo, PageQuery, PagedResult } from "@grdr/api";

const EMPTY_PAGE_INFO: PageInfo = {
  next_page_token: "",
  prev_page_token: "",
  total_size_estimate: 0,
  has_more: false,
};

export interface ServerPageState<T> {
  items: T[];
  pageInfo: PageInfo;
  pageIndex: number;
  pageSize: number;
  loading: boolean;
  error: string | null;
  goNext: () => void;
  goPrev: () => void;
  setPageSize: (size: number) => void;
  refresh: () => void;
}

export function useServerPage<T>(
  fetcher: (q: PageQuery) => Promise<PagedResult<T>>,
  filter: string,
  orderBy: string,
  initialPageSize = 25,
  refreshKey = 0,
): ServerPageState<T> {
  const [pageSize, setPageSizeState] = useState(initialPageSize);
  const [pageToken, setPageToken] = useState("");
  const [pageIndex, setPageIndex] = useState(0);
  const [items, setItems] = useState<T[]>([]);
  const [pageInfo, setPageInfo] = useState<PageInfo>(EMPTY_PAGE_INFO);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);

  useEffect(() => {
    setPageToken("");
    setPageIndex(0);
  }, [filter, orderBy, pageSize]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    void fetcher({
      page_size: pageSize,
      page_token: pageToken,
      filter,
      order_by: orderBy,
    })
      .then((res) => {
        if (!active) return;
        setItems(res.items);
        setPageInfo(res.page_info);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed loading page");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [fetcher, pageSize, pageToken, filter, orderBy, reloadNonce, refreshKey]);

  const goNext = useCallback(() => {
    if (!pageInfo.next_page_token) return;
    setPageToken(pageInfo.next_page_token);
    setPageIndex((i) => i + 1);
  }, [pageInfo.next_page_token]);

  const goPrev = useCallback(() => {
    if (!pageInfo.prev_page_token) return;
    setPageToken(pageInfo.prev_page_token);
    setPageIndex((i) => Math.max(0, i - 1));
  }, [pageInfo.prev_page_token]);

  const setPageSize = useCallback((size: number) => {
    setPageSizeState(size);
    setPageToken("");
    setPageIndex(0);
  }, []);

  const refresh = useCallback(() => {
    setReloadNonce((n) => n + 1);
  }, []);

  return {
    items,
    pageInfo,
    pageIndex,
    pageSize,
    loading,
    error,
    goNext,
    goPrev,
    setPageSize,
    refresh,
  };
}

export function aipQuote(value: string): string {
  const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `"${escaped}"`;
}
