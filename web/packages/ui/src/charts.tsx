import { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";

function readToken(name: string, fallback: string): string {
  if (typeof window === "undefined" || typeof document === "undefined") return fallback;
  const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return val || fallback;
}

function useThemeTick(): string {
  const [themeAttr, setThemeAttr] = useState(() =>
    typeof document !== "undefined"
      ? document.documentElement.getAttribute("data-theme") ?? "light"
      : "light",
  );

  useEffect(() => {
    if (typeof document === "undefined" || typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(() => {
      setThemeAttr(document.documentElement.getAttribute("data-theme") ?? "light");
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    return () => observer.disconnect();
  }, []);

  return themeAttr;
}

function canUseCanvas2d(): boolean {
  if (typeof document === "undefined") return false;
  if (typeof navigator !== "undefined" && /jsdom/i.test(navigator.userAgent)) return false;
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("2d"));
  } catch {
    return false;
  }
}

export interface FleetHexCell {
  key: string;
  col: number;
  row: number;
  deviceId: string | null;
  status: "boundary" | "partial" | "blind" | "empty";
  label: string;
}

export function GrdrChart({
  option,
  width = "100%",
  height,
  ariaLabel,
  onPointClick,
}: {
  option: echarts.EChartsOption;
  width?: number | string;
  height: number | string;
  ariaLabel: string;
  onPointClick?: (dataIndex: number) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);
  const clickRef = useRef(onPointClick);
  clickRef.current = onPointClick;

  useEffect(() => {
    const el = containerRef.current;
    if (!el || !canUseCanvas2d()) return;

    const instance = echarts.init(el, undefined, { renderer: "canvas" });
    chartRef.current = instance;
    instance.setOption(option);

    const handleClick = (params: echarts.ECElementEvent) => {
      if (typeof params.dataIndex === "number" && clickRef.current) {
        clickRef.current(params.dataIndex);
      }
    };
    instance.on("click", handleClick);

    const observer =
      typeof ResizeObserver !== "undefined"
        ? new ResizeObserver(() => {
            instance.resize();
          })
        : null;
    observer?.observe(el);

    return () => {
      observer?.disconnect();
      instance.off("click", handleClick);
      instance.dispose();
      chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(option, { notMerge: true });
  }, [option]);

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label={ariaLabel}
      style={{ width, height }}
    />
  );
}

export function GrdrCoverageRing({
  valuePct,
  label,
  size = 132,
  tone = "accent",
  compact = false,
}: {
  valuePct: number;
  label?: string;
  size?: number;
  tone?: "allow" | "accent";
  compact?: boolean;
}) {
  const themeTick = useThemeTick();
  const clamped = Math.max(0, Math.min(100, Math.round(valuePct)));

  const option = useMemo<echarts.EChartsOption>(() => {
    const fg =
      tone === "allow"
        ? readToken("--tone-allow", "rgb(22, 101, 52)")
        : readToken("--accent-primary", "rgb(15, 82, 186)");
    const track = readToken("--border-strong", "rgb(207, 207, 200)");
    const ink = readToken("--ink-primary", "rgb(17, 17, 17)");
    const muted = readToken("--ink-muted", "rgb(118, 118, 112)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");

    return {
      animationDuration: 220,
      tooltip: {
        trigger: "item",
        backgroundColor: bgCanvas,
        borderColor: track,
        textStyle: { color: ink, fontSize: 12 },
        formatter: `{b}: {c}%`,
      },
      title: {
        text: `${clamped}%`,
        subtext: label ?? "",
        left: "center",
        top: label ? "33%" : "36%",
        itemGap: 2,
        textStyle: {
          color: ink,
          fontSize: compact ? 11 : 22,
          fontWeight: 700,
        },
        subtextStyle: {
          color: muted,
          fontSize: 11,
        },
      },
      series: [
        {
          type: "pie",
          radius: compact ? ["70%", "92%"] : ["74%", "90%"],
          center: ["50%", "50%"],
          startAngle: 90,
          silent: compact,
          label: { show: false },
          labelLine: { show: false },
          data: [
            {
              name: label ?? "Coverage",
              value: clamped,
              itemStyle: { color: fg, borderRadius: compact ? 3 : 6 },
            },
            {
              name: "Remaining",
              value: Math.max(0, 100 - clamped),
              itemStyle: { color: track },
            },
          ],
        },
      ],
    };
  }, [clamped, label, tone, compact, themeTick]);

  return (
    <GrdrChart
      option={option}
      width={size}
      height={size}
      ariaLabel={`${clamped} percent ${label ?? "coverage"}`}
    />
  );
}

export function GrdrVelocityChart({
  data,
  height = 140,
}: {
  data: ReadonlyArray<{ day: string; allowed: number; ask: number; block: number }>;
  height?: number;
}) {
  const themeTick = useThemeTick();

  const option = useMemo<echarts.EChartsOption>(() => {
    const borderStrong = readToken("--border-strong", "rgb(207, 207, 200)");
    const askColor = readToken("--tone-ask", "rgb(180, 83, 9)");
    const blockColor = readToken("--tone-block", "rgb(185, 28, 28)");
    const inkMuted = readToken("--ink-muted", "rgb(118, 118, 112)");
    const ink = readToken("--ink-primary", "rgb(17, 17, 17)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");

    return {
      animationDuration: 220,
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: bgCanvas,
        borderColor: borderStrong,
        textStyle: { color: ink, fontSize: 12 },
      },
      grid: { left: 8, right: 8, top: 10, bottom: 24, containLabel: false },
      xAxis: {
        type: "category",
        data: data.map((d) => `${d.day} (${d.allowed + d.ask + d.block})`),
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: inkMuted, fontSize: 11 },
      },
      yAxis: {
        type: "value",
        show: false,
      },
      series: [
        {
          name: "Allowed",
          type: "bar",
          stack: "total",
          barMaxWidth: 44,
          data: data.map((d) => d.allowed),
          itemStyle: { color: borderStrong, borderRadius: [0, 0, 3, 3] },
        },
        {
          name: "Ask",
          type: "bar",
          stack: "total",
          barMaxWidth: 44,
          data: data.map((d) => d.ask),
          itemStyle: { color: askColor, borderColor: bgCanvas, borderWidth: 0.5 },
        },
        {
          name: "Blocked",
          type: "bar",
          stack: "total",
          barMaxWidth: 44,
          data: data.map((d) => d.block),
          itemStyle: { color: blockColor, borderColor: bgCanvas, borderWidth: 0.5, borderRadius: [3, 3, 0, 0] },
        },
      ],
    };
  }, [data, themeTick]);

  return (
    <GrdrChart
      option={option}
      width="100%"
      height={height}
      ariaLabel="Seven-day decision distribution stacked bar chart"
    />
  );
}

export function GrdrSparkline({
  values,
  ariaLabel,
  width = 112,
  height = 34,
}: {
  values: ReadonlyArray<number>;
  ariaLabel: string;
  width?: number;
  height?: number;
}) {
  const themeTick = useThemeTick();

  const option = useMemo<echarts.EChartsOption>(() => {
    const accent = readToken("--accent-primary", "rgb(15, 82, 186)");
    const accentSoft = readToken("--accent-soft", "rgba(15, 82, 186, 0.10)");
    return {
      animation: false,
      grid: { left: 2, right: 2, top: 4, bottom: 2 },
      xAxis: {
        type: "category",
        show: false,
        data: values.map((_, idx) => idx),
      },
      yAxis: {
        type: "value",
        show: false,
        min: (val) => Math.max(0, val.min - 1),
      },
      series: [
        {
          type: "line",
          smooth: true,
          symbol: "none",
          lineStyle: { color: accent, width: 2 },
          areaStyle: { color: accentSoft },
          data: [...values],
        },
      ],
    };
  }, [values, themeTick]);

  return <GrdrChart option={option} width={width} height={height} ariaLabel={ariaLabel} />;
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

  const maxCol = Math.max(1, ...cells.map((c) => c.col));
  const maxRow = Math.max(1, ...cells.map((c) => c.row));

  const option = useMemo<echarts.EChartsOption>(() => {
    const allowColor = readToken("--tone-allow", "rgb(22, 101, 52)");
    const askColor = readToken("--tone-ask", "rgb(180, 83, 9)");
    const blockColor = readToken("--tone-block", "rgb(185, 28, 28)");
    const borderSubtle = readToken("--border-subtle", "rgb(230, 230, 224)");
    const borderStrong = readToken("--border-strong", "rgb(207, 207, 200)");
    const inkPrimary = readToken("--ink-primary", "rgb(17, 17, 17)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");

    const statusFill = (status: FleetHexCell["status"]) => {
      if (status === "boundary") return allowColor;
      if (status === "partial") return askColor;
      if (status === "blind") return blockColor;
      return borderSubtle;
    };

    const statusOpacity = (status: FleetHexCell["status"]) => {
      if (status === "boundary") return 0.58;
      if (status === "partial") return 0.52;
      if (status === "blind") return 0.58;
      return 0.45;
    };

    return {
      animation: false,
      tooltip: {
        trigger: "item",
        backgroundColor: bgCanvas,
        borderColor: borderStrong,
        textStyle: { color: inkPrimary, fontSize: 12 },
        formatter: (params) => {
          const item = params as { dataIndex?: number };
          const cell = typeof item.dataIndex === "number" ? cells[item.dataIndex] : undefined;
          return cell ? cell.label : "";
        },
      },
      grid: { left: 16, right: 16, top: 12, bottom: 12 },
      xAxis: { type: "value", min: -0.5, max: Math.max(4, maxCol + 2.2), show: false },
      yAxis: { type: "value", min: -0.5, max: Math.max(2, maxRow + 1.4), inverse: true, show: false },
      series: [
        {
          type: "custom",
          renderItem: (params, api) => {
            const cell = cells[params.dataIndex];
            if (!cell) return null;
            const xUnit = cell.col + (cell.row % 2 === 1 ? 0.5 : 0) + 0.55;
            const yUnit = cell.row + 0.55;
            const center = api.coord([xUnit, yUnit]);
            const nextCol = api.coord([xUnit + 1, yUnit]);
            const spacingPx = Math.max(24, nextCol[0] - center[0]);
            const radius = Math.min(34, spacingPx * 0.44);

            const points: number[][] = [];
            for (let i = 0; i < 6; i++) {
              const angle = (Math.PI / 180) * (60 * i - 30);
              points.push([
                center[0] + radius * Math.cos(angle),
                center[1] + radius * Math.sin(angle),
              ]);
            }

            const baseColor = statusFill(cell.status);
            const isSelected = Boolean(cell.deviceId && cell.deviceId === selectedDeviceId);

            return {
              type: "polygon",
              shape: { points },
              style: {
                fill: baseColor,
                opacity: statusOpacity(cell.status),
                stroke: isSelected ? inkPrimary : baseColor,
                lineWidth: isSelected ? 2.2 : 1,
              },
            };
          },
          data: cells.map((c, idx) => [c.col, c.row, idx]),
        },
      ],
    };
  }, [cells, maxCol, maxRow, selectedDeviceId, themeTick]);

  return (
    <GrdrChart
      option={option}
      width="100%"
      height={height}
      ariaLabel="Interactive honeycomb hexbin map of fleet endpoints"
      onPointClick={(idx) => {
        const cell = cells[idx];
        if (cell?.deviceId) onSelectDevice(cell.deviceId);
      }}
    />
  );
}
