import { useEffect, useMemo, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import { graphlib, layout } from "@dagrejs/dagre";
import { GrdrIcon, type GrdrIconName, HarnessIcon } from "./components";

export type GrdrFlowTone = "accent" | "allow" | "watch" | "ask" | "block" | "neutral";

export interface GrdrFlowNode {
  id: string;
  label: string;
  subtitle?: string;
  badge?: string;
  tone?: GrdrFlowTone;
  icon?: GrdrIconName;
  harnessName?: string;
  selected?: boolean;
}

export interface GrdrFlowEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  dashed?: boolean;
  tone?: "neutral" | "block" | "allow" | "watch";
}

interface CustomNodeData extends Record<string, unknown> {
  label: string;
  subtitle?: string;
  badge?: string;
  tone: GrdrFlowTone;
  icon?: GrdrIconName;
  harnessName?: string;
  selected?: boolean;
  direction: "LR" | "TB";
}

type StudioNode = Node<CustomNodeData, "studio">;

const NODE_WIDTH = 172;
const NODE_HEIGHT = 104;

function iconToneColor(tone: GrdrFlowTone): string {
  switch (tone) {
    case "accent":
      return "var(--accent-primary)";
    case "allow":
      return "var(--tone-allow)";
    case "watch":
      return "var(--tone-watch)";
    case "ask":
      return "var(--tone-ask)";
    case "block":
      return "var(--tone-block)";
    default:
      return "var(--ink-secondary)";
  }
}

function edgeStroke(tone?: "neutral" | "block" | "allow" | "watch"): string {
  switch (tone) {
    case "block":
      return "var(--tone-block)";
    case "allow":
      return "var(--tone-allow)";
    case "watch":
      return "var(--tone-watch)";
    default:
      return "var(--border-strong)";
  }
}

function StudioFlowNodeView({ data }: NodeProps<StudioNode>) {
  const sourcePos = data.direction === "TB" ? Position.Bottom : Position.Right;
  const targetPos = data.direction === "TB" ? Position.Top : Position.Left;
  const handleStyle =
    data.direction === "LR" ? { opacity: 0, top: 22 } : { opacity: 0 };

  return (
    <div
      className="grdr-flow-node"
      data-direction={data.direction}
      data-tone={data.tone}
      data-selected={data.selected ? "true" : "false"}
    >
      <Handle type="target" position={targetPos} isConnectable={false} style={handleStyle} />
      <div className="grdr-flow-circle">
        {data.harnessName ? (
          <HarnessIcon name={data.harnessName} size={18} />
        ) : (
          <GrdrIcon
            name={data.icon ?? "shield"}
            size={18}
            color={iconToneColor(data.tone)}
          />
        )}
      </div>
      <div className="grdr-flow-node-title" title={data.label}>
        {data.label}
      </div>
      {data.subtitle ? (
        <div className="grdr-flow-node-sub" title={data.subtitle}>
          {data.subtitle}
        </div>
      ) : null}
      <Handle type="source" position={sourcePos} isConnectable={false} style={handleStyle} />
    </div>
  );
}

const NODE_TYPES: NodeTypes = {
  studio: StudioFlowNodeView,
};

function computeLayout(
  inputNodes: ReadonlyArray<GrdrFlowNode>,
  inputEdges: ReadonlyArray<GrdrFlowEdge>,
  direction: "LR" | "TB",
): { nodes: StudioNode[]; edges: Edge[] } {
  const graph = new graphlib.Graph();
  graph.setDefaultEdgeLabel(() => ({}));
  graph.setGraph({
    rankdir: direction,
    nodesep: direction === "LR" ? 28 : 42,
    ranksep: direction === "LR" ? 92 : 64,
    marginx: 24,
    marginy: 28,
  });

  for (const n of inputNodes) {
    graph.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  }
  for (const e of inputEdges) {
    graph.setEdge(e.source, e.target);
  }
  layout(graph);

  const nodes: StudioNode[] = inputNodes.map((n) => {
    const pos = graph.node(n.id);
    return {
      id: n.id,
      type: "studio",
      position: {
        x: (pos?.x ?? 0) - NODE_WIDTH / 2,
        y: (pos?.y ?? 0) - NODE_HEIGHT / 2,
      },
      data: {
        label: n.label,
        subtitle: n.subtitle,
        badge: n.badge,
        tone: n.tone ?? "neutral",
        icon: n.icon,
        harnessName: n.harnessName,
        selected: n.selected,
        direction,
      },
      draggable: false,
      selectable: true,
    };
  });

  const edges: Edge[] = inputEdges.map((e) => {
    const color = edgeStroke(e.tone);
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      type: "bezier",
      animated: false,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 14,
        height: 14,
        color,
      },
      style: {
        stroke: color,
        strokeWidth: 1.7,
        strokeDasharray: e.dashed ? "5 4" : undefined,
      },
    };
  });

  return { nodes, edges };
}

function useIsCompactViewport(): boolean {
  const [compact, setCompact] = useState(() =>
    typeof window !== "undefined" && typeof window.matchMedia === "function"
      ? window.matchMedia("(max-width: 640px)").matches
      : false,
  );
  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia("(max-width: 640px)");
    const update = () => setCompact(mql.matches);
    update();
    mql.addEventListener("change", update);
    return () => mql.removeEventListener("change", update);
  }, []);
  return compact;
}

export function GrdrFlowGraph({
  nodes,
  edges,
  direction = "LR",
  height = 300,
  ariaLabel,
  onNodeSelect,
}: {
  nodes: ReadonlyArray<GrdrFlowNode>;
  edges: ReadonlyArray<GrdrFlowEdge>;
  direction?: "LR" | "TB";
  height?: number;
  ariaLabel: string;
  onNodeSelect?: (nodeId: string) => void;
}) {
  const compactViewport = useIsCompactViewport();
  const effectiveDirection: "LR" | "TB" = compactViewport ? "TB" : direction;
  const effectiveHeight = effectiveDirection === "TB" ? Math.max(height, 290) : height;
  const layouted = useMemo(
    () => computeLayout(nodes, edges, effectiveDirection),
    [nodes, edges, effectiveDirection],
  );

  const canRenderFlow =
    typeof window !== "undefined" && typeof globalThis.DOMMatrixReadOnly !== "undefined";

  if (!canRenderFlow) {
    return (
      <div
        className="grdr-flow-wrap"
        role="region"
        aria-label={ariaLabel}
        style={{ height: effectiveHeight, padding: 12, display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}
      >
        {nodes.map((node) => (
          <button
            key={node.id}
            type="button"
            className="grdr-flow-node"
            data-tone={node.tone ?? "neutral"}
            data-selected={node.selected ? "true" : "false"}
            onClick={() => onNodeSelect?.(node.id)}
          >
            <div className="grdr-flow-circle">
              <span className="grdr-flow-badge" data-tone={node.tone ?? "neutral"}>
                {node.badge ?? node.label.slice(0, 2)}
              </span>
            </div>
            <span className="grdr-flow-node-title">{node.label}</span>
            {node.subtitle ? <div className="grdr-flow-node-sub">{node.subtitle}</div> : null}
          </button>
        ))}
      </div>
    );
  }

  return (
    <div
      className="grdr-flow-wrap"
      role="region"
      aria-label={ariaLabel}
      style={{ height: effectiveHeight }}
    >
      <ReactFlow
        key={`${effectiveDirection}-${nodes.length}-${NODE_WIDTH}`}
        nodes={layouted.nodes}
        edges={layouted.edges}
        nodeTypes={NODE_TYPES}
        minZoom={0.35}
        fitView
        fitViewOptions={{ padding: 0.24, maxZoom: 1.0 }}
        nodesDraggable={false}
        nodesConnectable={false}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => onNodeSelect?.(node.id)}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
        <Controls position="bottom-left" orientation="horizontal" showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
