import type { PageInfo } from "@grdr/api";
import { Pagination, Text } from "@grdr/ui";

export function formatRangeLabel(startIdx: number, pageSize: number, total: number): string {
  if (total === 0) return "Showing 0 of 0";
  return `Showing ${startIdx + 1}-${Math.min(startIdx + pageSize, total)} of ${total}`;
}

function buildPageSizeOptions(pageSize: number): number[] {
  return Array.from(new Set([pageSize, 25, 50, 100])).sort((a, b) => a - b);
}

export function PagerBar({
  page,
  pageSize,
  totalItems,
  label,
  onPageChange,
  onPageSizeChange,
}: {
  page: number;
  pageSize: number;
  totalItems: number;
  label: string;
  onPageChange: (nextPageZeroBased: number) => void;
  onPageSizeChange: (nextPageSize: number) => void;
}) {
  if (totalItems === 0) return null;
  const startIdx = page * pageSize;

  return (
    <div className="pager-bar">
      <Text size="sm" color="secondary" className="tabular">
        {formatRangeLabel(startIdx, pageSize, totalItems)}
      </Text>
      <Pagination
        page={page + 1}
        onChange={(p) => onPageChange(Math.max(0, p - 1))}
        totalItems={totalItems}
        pageSize={pageSize}
        pageSizeOptions={buildPageSizeOptions(pageSize)}
        onPageSizeChange={(sz) => onPageSizeChange(sz)}
        variant="count"
        size="sm"
        label={label}
      />
    </div>
  );
}

export function CursorPagerBar({
  pageIndex,
  pageSize,
  itemCount,
  pageInfo,
  label,
  onNext,
  onPrev,
  onPageSizeChange,
}: {
  pageIndex: number;
  pageSize: number;
  itemCount: number;
  pageInfo: PageInfo;
  label: string;
  onNext: () => void;
  onPrev: () => void;
  onPageSizeChange: (nextPageSize: number) => void;
}) {
  const total = pageInfo.total_size_estimate;
  if (total === 0 && itemCount === 0) return null;
  const startIdx = pageIndex * pageSize;
  const effectiveTotal = Math.max(total, startIdx + itemCount);

  return (
    <div className="pager-bar">
      <Text size="sm" color="secondary" className="tabular">
        {formatRangeLabel(startIdx, Math.max(itemCount, 1), effectiveTotal)}
      </Text>
      <Pagination
        page={pageIndex + 1}
        onChange={(nextOneBased) => {
          const target = nextOneBased - 1;
          if (target > pageIndex && pageInfo.next_page_token) {
            onNext();
          } else if (target < pageIndex && pageInfo.prev_page_token) {
            onPrev();
          }
        }}
        totalItems={effectiveTotal}
        pageSize={pageSize}
        pageSizeOptions={buildPageSizeOptions(pageSize)}
        onPageSizeChange={(sz) => onPageSizeChange(sz)}
        variant="count"
        size="sm"
        label={label}
      />
    </div>
  );
}
