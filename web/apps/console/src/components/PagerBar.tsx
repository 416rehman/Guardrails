import { Pagination, Text } from "@grdr/ui";

export function formatRangeLabel(startIdx: number, pageSize: number, total: number): string {
  if (total === 0) return "Showing 0 of 0";
  return `Showing ${startIdx + 1}-${Math.min(startIdx + pageSize, total)} of ${total}`;
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
        pageSizeOptions={[25, 50, 100]}
        onPageSizeChange={(sz) => onPageSizeChange(sz)}
        variant="count"
        size="sm"
        label={label}
      />
    </div>
  );
}
