import { useCallback, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { PageInfo, PageQuery, PagedResult } from "@grdr/api";
import { CONSOLE_SCOPE } from "../queries";

const EMPTY_PAGE_INFO: PageInfo = {
  next_page_token: "",
  prev_page_token: "",
  total_size_estimate: 0,
  has_more: false,
};

export interface ServerPageUrlOptions {
  resource?: string;
  pageToken?: string;
  pageIndex?: number;
  pageSize?: number;
  onPageChange?: (next: { pageToken: string; pageIndex: number }) => void;
  onPageSizeChange?: (nextSize: number) => void;
}

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
  options?: ServerPageUrlOptions,
): ServerPageState<T> {
  const queryClient = useQueryClient();
  const [localPageSize, setLocalPageSize] = useState(initialPageSize);
  const [localPageToken, setLocalPageToken] = useState("");
  const [localPageIndex, setLocalPageIndex] = useState(0);

  const isUrlControlled = options?.onPageChange !== undefined;
  const pageToken = isUrlControlled ? (options.pageToken ?? "") : localPageToken;
  const pageIndex = isUrlControlled ? (options.pageIndex ?? 0) : localPageIndex;
  const pageSize =
    options?.pageSize && options.pageSize > 0 ? options.pageSize : localPageSize;
  const resource = options?.resource ?? orderBy;

  const scopeKey = `${filter}\0${orderBy}\0${pageSize}`;
  const [settledScopeKey, setSettledScopeKey] = useState(scopeKey);
  const scopeMismatch = settledScopeKey !== scopeKey;
  const effectivePageToken = scopeMismatch ? "" : pageToken;
  const effectivePageIndex = scopeMismatch ? 0 : pageIndex;

  useEffect(() => {
    if (!scopeMismatch) return;
    if (isUrlControlled) {
      if (pageToken !== "" || pageIndex !== 0) {
        options.onPageChange?.({ pageToken: "", pageIndex: 0 });
        return;
      }
      setSettledScopeKey(scopeKey);
    } else {
      setLocalPageToken("");
      setLocalPageIndex(0);
      setSettledScopeKey(scopeKey);
    }
  }, [scopeMismatch, scopeKey, isUrlControlled, options, pageToken, pageIndex]);

  const query = useQuery({
    queryKey: [
      CONSOLE_SCOPE,
      resource,
      { filter, orderBy, pageSize, pageToken: effectivePageToken, refreshKey },
    ],
    queryFn: () =>
      fetcher({
        page_size: pageSize,
        page_token: effectivePageToken,
        filter,
        order_by: orderBy,
      }),
  });

  const pageInfo = query.data?.page_info ?? EMPTY_PAGE_INFO;
  const items = query.data?.items ?? [];
  const error =
    query.error instanceof Error
      ? query.error.message
      : query.error
        ? "Failed loading page"
        : null;

  const goNext = useCallback(() => {
    if (!pageInfo.next_page_token) return;
    if (isUrlControlled) {
      options.onPageChange?.({
        pageToken: pageInfo.next_page_token,
        pageIndex: pageIndex + 1,
      });
    } else {
      setLocalPageToken(pageInfo.next_page_token);
      setLocalPageIndex((i) => i + 1);
    }
  }, [pageInfo.next_page_token, isUrlControlled, options, pageIndex]);

  const goPrev = useCallback(() => {
    if (!pageInfo.prev_page_token) return;
    if (isUrlControlled) {
      options.onPageChange?.({
        pageToken: pageInfo.prev_page_token,
        pageIndex: Math.max(0, pageIndex - 1),
      });
    } else {
      setLocalPageToken(pageInfo.prev_page_token);
      setLocalPageIndex((i) => Math.max(0, i - 1));
    }
  }, [pageInfo.prev_page_token, isUrlControlled, options, pageIndex]);

  const setPageSize = useCallback(
    (size: number) => {
      if (options?.onPageSizeChange) {
        options.onPageSizeChange(size);
      } else {
        setLocalPageSize(size);
      }
      if (isUrlControlled) {
        options.onPageChange?.({ pageToken: "", pageIndex: 0 });
      } else {
        setLocalPageToken("");
        setLocalPageIndex(0);
      }
    },
    [isUrlControlled, options],
  );

  const refresh = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: [CONSOLE_SCOPE, resource] });
  }, [queryClient, resource]);

  return {
    items,
    pageInfo,
    pageIndex: effectivePageIndex,
    pageSize,
    loading: query.isLoading,
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
