import { GrdrIcon } from "@grdr/ui";

export interface BreadcrumbItem {
  id: string;
  label: string;
  onClick?: () => void;
}

export function Breadcrumbs({ items }: { items: ReadonlyArray<BreadcrumbItem> }) {
  if (items.length === 0) return null;

  return (
    <nav aria-label="Breadcrumb" className="breadcrumbs">
      <ol className="breadcrumb-list">
        {items.map((item, idx) => {
          const isLeaf = idx === items.length - 1;
          return (
            <li key={item.id} className="breadcrumb-item">
              {idx > 0 && (
                <span className="breadcrumb-sep" aria-hidden="true">
                  <GrdrIcon name="chevron-right" size={12} color="var(--ink-muted)" />
                </span>
              )}
              {isLeaf || !item.onClick ? (
                <span
                  className={isLeaf ? "breadcrumb-current" : "breadcrumb-ancestor-text"}
                  aria-current={isLeaf ? "page" : undefined}
                >
                  {item.label}
                </span>
              ) : (
                <button
                  type="button"
                  className="breadcrumb-link"
                  onClick={item.onClick}
                >
                  {item.label}
                </button>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
