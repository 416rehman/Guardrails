import { useEffect, useMemo, useRef, useState } from "react";
import type * as echarts from "echarts";
import { GrdrChart, readToken, useThemeTick } from "./charts";

export interface FleetHexCell {
  key: string;
  col: number;
  row: number;
  deviceId: string | null;
  status: "boundary" | "partial" | "blind" | "empty";
  label: string;
}

export function GrdrFleetHexMap({
  cells,
  selectedDeviceId,
  onSelectDevice,
  height = 204,
}: {
  cells: ReadonlyArray<FleetHexCell>;
  selectedDeviceId: string | null;
  onSelectDevice: (deviceId: string) => void;
  height?: number;
}) {
  const themeTick = useThemeTick();
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [containerWidth, setContainerWidth] = useState<number>(() =>
    typeof window !== "undefined" ? window.innerWidth : 900,
  );

  useEffect(() => {
    const node = wrapRef.current;
    if (!node || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      const w = node.getBoundingClientRect().width;
      if (w > 0) setContainerWidth(w);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(node);
    return () => ro.disconnect();
  }, []);

  const isNarrow = containerWidth > 0 && containerWidth < 460;
  const maxColsNarrow = containerWidth > 0 && containerWidth < 260 ? 1 : 2;

  const displayCells = useMemo<FleetHexCell[]>(() => {
    if (!isNarrow) return [...cells];
    return cells.map((c, idx) => ({
      ...c,
      col: idx % maxColsNarrow,
      row: Math.floor(idx / maxColsNarrow),
    }));
  }, [cells, isNarrow, maxColsNarrow]);

  const maxCol = Math.max(0, ...displayCells.map((c) => c.col));
  const maxRow = Math.max(0, ...displayCells.map((c) => c.row));
  const effectiveHeight = isNarrow
    ? Math.max(height, (maxRow + 1) * 96 + 24)
    : height;

  const option = useMemo<echarts.EChartsOption>(() => {
    const allowEdge = readToken("--tone-allow", "rgb(21, 128, 61)");
    const allowFill = readToken("--tone-allow-bg", "rgba(21, 128, 61, 0.12)");
    const askEdge = readToken("--tone-ask", "rgb(161, 98, 7)");
    const askFill = readToken("--tone-ask-bg", "rgba(250, 204, 21, 0.16)");
    const blockEdge = readToken("--tone-block", "rgb(185, 28, 28)");
    const blockFill = readToken("--tone-block-bg", "rgba(185, 28, 28, 0.12)");

    const borderStrong = readToken("--border-strong", "rgb(209, 213, 219)");
    const inkPrimary = readToken("--ink-primary", "rgb(15, 23, 42)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");
    const sansFont = readToken("--font-sans", "DM Sans, sans-serif");

    const hexColors = (status: FleetHexCell["status"]) => {
      if (status === "boundary") return { fill: allowFill, edge: allowEdge };
      if (status === "partial") return { fill: askFill, edge: askEdge };
      return { fill: blockFill, edge: blockEdge };
    };

    const hexPolygon = (cx: number, cy: number, r: number): number[][] => {
      const pts: number[][] = [];
      for (let i = 0; i < 6; i += 1) {
        const angle = (Math.PI / 180) * (60 * i - 30);
        pts.push([cx + r * Math.cos(angle), cy + r * Math.sin(angle)]);
      }
      return pts;
    };

    return {
      animation: false,
      tooltip: {
        trigger: "item",
        backgroundColor: bgCanvas,
        borderColor: borderStrong,
        textStyle: { color: inkPrimary, fontSize: 12, fontFamily: sansFont },
        formatter: (params) => {
          const item = params as { dataIndex?: number };
          const cell = typeof item.dataIndex === "number" ? displayCells[item.dataIndex] : undefined;
          return cell && cell.label ? cell.label : "";
        },
      },
      grid: { left: isNarrow ? 32 : 20, right: isNarrow ? 32 : 20, top: 8, bottom: 12 },
      xAxis: {
        type: "value",
        min: maxCol === 0 ? -1 : isNarrow ? -0.75 : -0.6,
        max: maxCol === 0 ? 1 : maxCol + (isNarrow ? 0.75 : 0.6),
        show: false,
      },
      yAxis: {
        type: "value",
        min: maxRow === 0 ? -0.6 : -0.5,
        max: maxRow === 0 ? 0.85 : maxRow + 0.85,
        inverse: true,
        show: false,
      },
      series: [
        {
          type: "custom",
          renderItem: (params, api) => {
            const cell = displayCells[params.dataIndex];
            if (!cell || cell.status === "empty") return null;
            const center = api.coord([cell.col, cell.row]);
            const radius = isNarrow ? 22 : 26;
            const outerPts = hexPolygon(center[0], center[1] - 6, radius);
            const palette = hexColors(cell.status);
            const isSelected = Boolean(cell.deviceId && cell.deviceId === selectedDeviceId);
            const shortLabel = cell.label.split("·")[0]?.trim() ?? cell.label;

            type CustomChild = NonNullable<echarts.CustomSeriesRenderItemReturn>;
            const children: CustomChild[] = [
              {
                type: "polygon",
                shape: { points: outerPts },
                style: {
                  fill: palette.fill,
                  stroke: isSelected ? inkPrimary : palette.edge,
                  lineWidth: isSelected ? 2 : 1.5,
                },
              },
              {
                type: "circle",
                silent: true,
                shape: { cx: center[0], cy: center[1] - 6, r: 4 },
                style: { fill: palette.edge },
              },
              {
                type: "text",
                silent: true,
                style: {
                  text: shortLabel,
                  x: center[0],
                  y: center[1] + radius + 6,
                  align: "center",
                  fill: inkPrimary,
                  fontSize: isNarrow ? 11 : 12,
                  fontWeight: isSelected ? 600 : 500,
                  fontFamily: sansFont,
                  width: isNarrow ? 116 : 168,
                  overflow: "truncate",
                },
              },
            ];

            return {
              type: "group",
              children,
            };
          },
          data: displayCells.map((c, idx) => [c.col, c.row, idx]),
        },
      ],
    };
  }, [displayCells, isNarrow, maxCol, maxRow, selectedDeviceId, themeTick]);

  return (
    <div ref={wrapRef} style={{ width: "100%" }}>
      <GrdrChart
        option={option}
        width="100%"
        height={effectiveHeight}
        ariaLabel="Interactive honeycomb hexbin map of fleet endpoints"
        onPointClick={(idx) => {
          const cell = displayCells[idx];
          if (cell?.deviceId) onSelectDevice(cell.deviceId);
        }}
      />
    </div>
  );
}
