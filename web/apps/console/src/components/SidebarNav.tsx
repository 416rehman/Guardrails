import { useEffect, useState } from "react";
import { CONSOLE_NAV_GROUPS, pluralize, t, type ConsoleRouteId } from "@grdr/i18n";
import {
  GrdrIcon,
  GuardrailsMark,
  IconButton,
  Tooltip,
  iconKeyToName,
  type GrdrIconName,
} from "@grdr/ui";

export interface SidebarNavProps {
  route: ConsoleRouteId;
  activeChildId: string | null;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onSelectRoute: (route: ConsoleRouteId) => void;
  onSelectChild: (route: ConsoleRouteId, childId: string) => void;
  pendingApprovals: number;
  streamDisconnected: boolean;
  deviceCount: number;
  sessionCount: number;
}

export function SidebarNav({
  route,
  activeChildId,
  collapsed,
  onToggleCollapse,
  onSelectRoute,
  onSelectChild,
  pendingApprovals,
  streamDisconnected,
  deviceCount,
  sessionCount,
}: SidebarNavProps) {
  const [expandedRoutes, setExpandedRoutes] = useState<Record<string, boolean>>({
    inventory: true,
    sessions: false,
    protect: false,
  });

  useEffect(() => {
    const activeItem = CONSOLE_NAV_GROUPS.flatMap((g) => g.items).find((item) => item.id === route);
    if (activeItem?.children?.length) {
      setExpandedRoutes((prev) => (prev[route] ? prev : { ...prev, [route]: true }));
    }
  }, [route]);

  const activeParentWithChildren = CONSOLE_NAV_GROUPS.flatMap((g) => g.items).find(
    (item) => item.id === route && item.children && item.children.length > 0,
  );

  function toggleExpanded(itemId: ConsoleRouteId) {
    setExpandedRoutes((prev) => ({ ...prev, [itemId]: !prev[itemId] }));
  }

  return (
    <aside className={collapsed ? "rail collapsed" : "rail"} aria-label="Primary navigation">
      <div className="brand-header">
        <div className="brand-mark">
          <div className="brand-glyph">
            <GuardrailsMark size={18} />
          </div>
          {!collapsed && (
            <div className="brand-title">
              <strong>{t("grdr.brand.name")}</strong>
              <span>{t("grdr.brand.subtitle")}</span>
            </div>
          )}
        </div>
        <span className="rail-collapse-btn">
          <IconButton
            label={collapsed ? "Expand navigation" : "Collapse navigation"}
            icon={
              <GrdrIcon
                name={collapsed ? "panel-left-open" : "panel-left-close"}
                size={15}
              />
            }
            variant="ghost"
            size="sm"
            onClick={onToggleCollapse}
          />
        </span>
      </div>

      <nav className="rail-nav" aria-label="Console sections">
        {CONSOLE_NAV_GROUPS.map((group) => (
          <div key={group.id} className="rail-group">
            {!collapsed && <div className="rail-group-label">{t(group.labelKey)}</div>}
            <div className="rail-group-items">
              {group.items.map((item) => {
                const label = t(item.labelKey);
                const hasChildren = Boolean(item.children && item.children.length > 0);
                const isExpanded = Boolean(expandedRoutes[item.id]);
                const isRouteActive = route === item.id;
                const buttonNode = (
                  <button
                    type="button"
                    title={label}
                    aria-label={label}
                    aria-current={isRouteActive && !hasChildren ? "page" : undefined}
                    aria-expanded={hasChildren ? isExpanded : undefined}
                    className={`nav-item ${isRouteActive ? "active" : ""}`}
                    onClick={() => {
                      if (hasChildren) {
                        setExpandedRoutes((prev) => ({ ...prev, [item.id]: true }));
                      }
                      onSelectRoute(item.id);
                    }}
                  >
                    <span className="nav-item-label">
                      <GrdrIcon name={iconKeyToName(item.iconKey)} size={16} />
                      {!collapsed && <span>{label}</span>}
                    </span>
                    {!collapsed && item.id === "respond" && pendingApprovals > 0 && (
                      <span
                        className="nav-attention-count tabular"
                        aria-label={`${pendingApprovals} pending`}
                      >
                        {pendingApprovals}
                      </span>
                    )}
                  </button>
                );

                return (
                  <div key={item.id} className="nav-node">
                    <div className="nav-parent-row">
                      {collapsed ? (
                        <Tooltip content={label} placement="end">
                          {buttonNode}
                        </Tooltip>
                      ) : (
                        buttonNode
                      )}
                      {!collapsed && hasChildren && (
                        <button
                          type="button"
                          className="nav-chevron-btn"
                          aria-label={`Toggle ${label} sub-navigation`}
                          aria-expanded={isExpanded}
                          onClick={() => toggleExpanded(item.id)}
                        >
                          <GrdrIcon
                            name={isExpanded ? "chevron-down" : "chevron-right"}
                            size={13}
                          />
                        </button>
                      )}
                    </div>

                    {!collapsed && hasChildren && isExpanded && item.children && (
                      <div className="nav-sublist" role="group" aria-label={`${label} views`}>
                        {item.children.map((child) => {
                          const childLabel = t(child.labelKey);
                          const isChildActive = isRouteActive && activeChildId === child.id;
                          return (
                            <button
                              key={child.id}
                              type="button"
                              className={`nav-subitem ${isChildActive ? "active" : ""}`}
                              aria-current={isChildActive ? "page" : undefined}
                              onClick={() => onSelectChild(item.id, child.id)}
                            >
                              <GrdrIcon
                                name={child.iconKey as GrdrIconName}
                                size={13}
                              />
                              <span>{childLabel}</span>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {activeParentWithChildren?.children && (
        <div
          className="mobile-subnav"
          role="group"
          aria-label={`${t(activeParentWithChildren.labelKey)} views`}
        >
          {activeParentWithChildren.children.map((child) => {
            const childLabel = t(child.labelKey);
            const isChildActive = activeChildId === child.id;
            return (
              <button
                key={child.id}
                type="button"
                className={`mobile-subnav-item ${isChildActive ? "active" : ""}`}
                aria-current={isChildActive ? "page" : undefined}
                onClick={() => onSelectChild(activeParentWithChildren.id, child.id)}
              >
                <GrdrIcon name={child.iconKey as GrdrIconName} size={12} />
                <span>{childLabel}</span>
              </button>
            );
          })}
        </div>
      )}

      {!collapsed && (
        <div className="rail-footer">
          {streamDisconnected && (
            <div style={{ color: "var(--tone-ask)" }}>{t("console.stream.reconnecting")}</div>
          )}
          <div className="tabular">
            {`${pluralize(deviceCount, "endpoint")}, ${pluralize(sessionCount, "session")}`}
          </div>
        </div>
      )}
    </aside>
  );
}
