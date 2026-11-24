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
    const fgStart =
      tone === "allow"
        ? readToken("--viz-allow-start", "rgb(20, 184, 166)")
        : readToken("--viz-watch-start", "rgb(37, 99, 235)");
    const fgEnd =
      tone === "allow"
        ? readToken("--viz-allow-end", "rgb(15, 118, 110)")
        : readToken("--viz-watch-end", "rgb(15, 82, 186)");
    const fgGlow =
      tone === "allow"
        ? readToken("--viz-allow-glow", "rgba(15, 118, 110, 0.22)")
        : readToken("--viz-watch-glow", "rgba(15, 82, 186, 0.22)");
    const dialTrack = readToken("--viz-dial-track", "rgb(223, 223, 215)");
    const dialTick = readToken("--viz-dial-tick", "rgba(17, 17, 17, 0.22)");
    const gridLine = readToken("--viz-grid-line", "rgba(17, 17, 17, 0.08)");
    const track = readToken("--border-strong", "rgb(207, 207, 200)");
    const ink = readToken("--ink-primary", "rgb(17, 17, 17)");
    const muted = readToken("--ink-muted", "rgb(99, 99, 93)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");
    const sansFont = readToken("--font-sans", "DM Sans, sans-serif");
    const gradient = new echarts.graphic.LinearGradient(0, 0, 1, 1, [
      { offset: 0, color: fgStart },
      { offset: 1, color: fgEnd },
    ]);

    if (compact) {
      return {
        animationDuration: 220,
        series: [
          {
            type: "gauge",
            startAngle: 90,
            endAngle: -270,
            radius: "92%",
            silent: true,
            pointer: { show: false },
            axisLine: { lineStyle: { width: 5, color: [[1, dialTrack]] } },
            progress: {
              show: true,
              roundCap: true,
              width: 5,
              itemStyle: { color: gradient },
            },
            splitNumber: 4,
            splitLine: { show: true, length: 3, distance: 1, lineStyle: { color: dialTick, width: 1 } },
            axisTick: { show: false },
            axisLabel: { show: false },
            detail: {
              valueAnimation: false,
              offsetCenter: [0, 0],
              fontSize: 11,
              fontWeight: 700,
              fontFamily: sansFont,
              color: ink,
              formatter: "{value}%",
            },
            title: { show: false },
            data: [{ value: clamped }],
          },
        ],
      };
    }

    return {
      animationDuration: 220,
      tooltip: {
        trigger: "item",
        backgroundColor: bgCanvas,
        borderColor: track,
        textStyle: { color: ink, fontSize: 12, fontFamily: sansFont },
        formatter: `{b}: {c}%`,
      },
      series: [
        {
          type: "gauge",
          startAngle: 220,
          endAngle: -40,
          radius: "92%",
          splitNumber: 10,
          axisLine: {
            roundCap: true,
            lineStyle: { width: 10, color: [[1, dialTrack]] },
          },
          progress: {
            show: true,
            roundCap: true,
            width: 10,
            itemStyle: {
              color: gradient,
              shadowBlur: 12,
              shadowColor: fgGlow,
            },
          },
          axisTick: {
            show: true,
            splitNumber: 3,
            length: 4,
            distance: 3,
            lineStyle: { color: dialTick, width: 1 },
          },
          splitLine: {
            show: true,
            length: 8,
            distance: 2,
            lineStyle: { color: muted, width: 1.5 },
          },
          pointer: { show: false },
          axisLabel: { show: false },
          detail: {
            valueAnimation: false,
            offsetCenter: [0, "-4%"],
            fontSize: 24,
            fontWeight: 700,
            fontFamily: sansFont,
            color: ink,
            formatter: "{value}%",
          },
          title: {
            offsetCenter: [0, "34%"],
            fontSize: 11.5,
            fontWeight: 500,
            fontFamily: sansFont,
            color: muted,
          },
          data: [{ value: clamped, name: label ?? "Boundary" }],
        },
        {
          type: "gauge",
          startAngle: 220,
          endAngle: -40,
          radius: "66%",
          silent: true,
          axisLine: { lineStyle: { width: 1, color: [[1, gridLine]] } },
          splitLine: { show: false },
          axisTick: { show: false },
          axisLabel: { show: false },
          pointer: { show: false },
          detail: { show: false },
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
  height = 152,
}: {
  data: ReadonlyArray<{ day: string; allowed: number; ask: number; block: number }>;
  height?: number;
}) {
  const themeTick = useThemeTick();

  const option = useMemo<echarts.EChartsOption>(() => {
    const borderStrong = readToken("--border-strong", "rgb(207, 207, 200)");
    const allowStart = readToken("--viz-allow-start", "rgb(20, 184, 166)");
    const allowEnd = readToken("--viz-allow-end", "rgb(15, 118, 110)");
    const allowGlow = readToken("--viz-allow-glow", "rgba(15, 118, 110, 0.22)");
    const askStart = readToken("--viz-ask-start", "rgb(245, 158, 11)");
    const askEnd = readToken("--viz-ask-end", "rgb(180, 83, 9)");
    const blockStart = readToken("--viz-block-start", "rgb(239, 68, 68)");
    const blockEnd = readToken("--viz-block-end", "rgb(185, 28, 28)");
    const decalInk = readToken("--viz-decal-ink", "rgba(255, 255, 255, 0.38)");
    const gridLine = readToken("--viz-grid-line", "rgba(17, 17, 17, 0.08)");
    const railTrack = readToken("--viz-rail-track", "rgba(17, 17, 17, 0.045)");
    const inkMuted = readToken("--ink-muted", "rgb(99, 99, 93)");
    const ink = readToken("--ink-primary", "rgb(17, 17, 17)");
    const bgRecessed = readToken("--bg-recessed", "rgb(243, 243, 240)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");
    const sansFont = readToken("--font-sans", "DM Sans, sans-serif");
    const monoFont = readToken("--font-mono", "IBM Plex Mono, monospace");

    const totals = data.map((d) => d.allowed + d.ask + d.block);
    const avgTotal = totals.length > 0 ? Math.round(totals.reduce((s, n) => s + n, 0) / totals.length) : 0;

    return {
      animationDuration: 220,
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow", shadowStyle: { color: railTrack } },
        backgroundColor: bgCanvas,
        borderColor: borderStrong,
        borderWidth: 1,
        textStyle: { color: ink, fontSize: 12, fontFamily: sansFont },
      },
      grid: { left: 32, right: 10, top: 14, bottom: 26, containLabel: false },
      xAxis: {
        type: "category",
        data: data.map((d) => `${d.day} (${d.allowed + d.ask + d.block})`),
        axisLine: { lineStyle: { color: gridLine } },
        axisTick: { show: false },
        axisLabel: { color: inkMuted, fontSize: 11, fontFamily: sansFont, margin: 10 },
      },
      yAxis: {
        type: "value",
        show: true,
        splitNumber: 3,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: inkMuted, fontSize: 10, fontFamily: monoFont },
        splitLine: { lineStyle: { color: gridLine, type: "dashed" } },
      },
      series: [
        {
          name: "Allowed",
          type: "bar",
          stack: "total",
          barMaxWidth: 36,
          barCategoryGap: "36%",
          showBackground: true,
          backgroundStyle: { color: railTrack, borderRadius: [5, 5, 4, 4] },
          data: data.map((d) => ({
            value: d.allowed,
            itemStyle: {
              borderRadius: d.ask === 0 && d.block === 0 ? [5, 5, 4, 4] : [2, 2, 4, 4],
            },
          })),
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: allowStart },
              { offset: 1, color: allowEnd },
            ]),
            borderColor: bgRecessed,
            borderWidth: 1,
          },
          emphasis: { itemStyle: { shadowBlur: 10, shadowColor: allowGlow } },
          markLine: {
            silent: true,
            symbol: "none",
            lineStyle: { color: inkMuted, type: "dotted", width: 1 },
            label: {
              show: true,
              position: "insideEndTop",
              formatter: `avg ${avgTotal}`,
              color: inkMuted,
              fontSize: 9.5,
              fontFamily: monoFont,
            },
            data: [{ yAxis: avgTotal }],
          },
        },
        {
          name: "Ask",
          type: "bar",
          stack: "total",
          barMaxWidth: 36,
          data: data.map((d) =>
            d.ask === 0 ? { value: 0, itemStyle: { borderWidth: 0 } } : d.ask,
          ),
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: askStart },
              { offset: 1, color: askEnd },
            ]),
            borderWidth: 0,
            decal: {
              symbol: "rect",
              dashArrayX: [1, 0],
              dashArrayY: [3, 3],
              rotation: -Math.PI / 4,
              color: decalInk,
            },
          },
        },
        {
          name: "Blocked",
          type: "bar",
          stack: "total",
          barMaxWidth: 36,
          data: data.map((d) =>
            d.block === 0 ? { value: 0, itemStyle: { borderWidth: 0 } } : d.block,
          ),
          itemStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: blockStart },
              { offset: 1, color: blockEnd },
            ]),
            borderWidth: 0,
            borderRadius: [4, 4, 0, 0],
            decal: {
              symbol: "rect",
              dashArrayX: [1, 0],
              dashArrayY: [2, 2],
              rotation: Math.PI / 4,
              color: decalInk,
            },
          },
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
    const watchStart = readToken("--viz-watch-start", "rgb(37, 99, 235)");
    const watchEdge = readToken("--viz-watch-edge", "rgb(29, 78, 216)");
    const watchGlow = readToken("--viz-watch-glow", "rgba(15, 82, 186, 0.22)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");
    const seriesData = values.map((v, idx) =>
      idx === values.length - 1
        ? {
            value: v,
            symbol: "circle",
            symbolSize: 5,
            itemStyle: { color: watchEdge, borderColor: bgCanvas, borderWidth: 1.5 },
          }
        : v,
    );
    return {
      animation: false,
      grid: { left: 2, right: 6, top: 6, bottom: 2 },
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
          lineStyle: { color: watchStart, width: 2, shadowBlur: 6, shadowColor: watchGlow },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: watchGlow },
              { offset: 1, color: "rgba(0, 0, 0, 0)" },
            ]),
          },
          data: seriesData,
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

  const displayCells = useMemo<FleetHexCell[]>(() => {
    if (cells.length >= 16) return [...cells];
    const occupied = new Map<string, FleetHexCell>();
    for (const c of cells) {
      occupied.set(`${c.col}:${c.row}`, c);
    }
    const cols = 8;
    const rows = 2;
    const lattice: FleetHexCell[] = [];
    for (let r = 0; r < rows; r += 1) {
      for (let c = 0; c < cols; c += 1) {
        const existing = occupied.get(`${c}:${r}`);
        lattice.push(
          existing ?? {
            key: `ghost-${c}-${r}`,
            col: c,
            row: r,
            deviceId: null,
            status: "empty",
            label: "",
          },
        );
      }
    }
    for (const c of cells) {
      if (c.col >= cols || c.row >= rows) lattice.push(c);
    }
    return lattice;
  }, [cells]);

  const maxCol = Math.max(1, ...displayCells.map((c) => c.col));
  const maxRow = Math.max(1, ...displayCells.map((c) => c.row));

  const option = useMemo<echarts.EChartsOption>(() => {
    const allowStart = readToken("--viz-allow-start", "rgb(20, 184, 166)");
    const allowEnd = readToken("--viz-allow-end", "rgb(15, 118, 110)");
    const allowEdge = readToken("--viz-allow-edge", "rgb(13, 148, 136)");
    const allowGlow = readToken("--viz-allow-glow", "rgba(15, 118, 110, 0.22)");

    const askStart = readToken("--viz-ask-start", "rgb(245, 158, 11)");
    const askEnd = readToken("--viz-ask-end", "rgb(180, 83, 9)");
    const askEdge = readToken("--viz-ask-edge", "rgb(217, 119, 6)");
    const askGlow = readToken("--viz-ask-glow", "rgba(180, 83, 9, 0.22)");

    const blockStart = readToken("--viz-block-start", "rgb(239, 68, 68)");
    const blockEnd = readToken("--viz-block-end", "rgb(185, 28, 28)");
    const blockEdge = readToken("--viz-block-edge", "rgb(220, 38, 38)");
    const blockGlow = readToken("--viz-block-glow", "rgba(185, 28, 28, 0.22)");

    const hexEmpty = readToken("--viz-hex-empty", "rgba(17, 17, 17, 0.03)");
    const hexEmptyStroke = readToken("--viz-hex-empty-stroke", "rgba(17, 17, 17, 0.12)");
    const specular = readToken("--surface-specular", "rgba(255, 255, 255, 0.65)");
    const decalInk = readToken("--viz-decal-ink", "rgba(255, 255, 255, 0.38)");
    const borderStrong = readToken("--border-strong", "rgb(207, 207, 200)");
    const inkPrimary = readToken("--ink-primary", "rgb(17, 17, 17)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");
    const sansFont = readToken("--font-sans", "DM Sans, sans-serif");

    const hexColors = (status: FleetHexCell["status"]) => {
      if (status === "boundary") {
        return { start: allowStart, end: allowEnd, edge: allowEdge, glow: allowGlow };
      }
      if (status === "partial") {
        return { start: askStart, end: askEnd, edge: askEdge, glow: askGlow };
      }
      return { start: blockStart, end: blockEnd, edge: blockEdge, glow: blockGlow };
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
      grid: { left: 16, right: 16, top: 10, bottom: 10 },
      xAxis: { type: "value", min: -0.2, max: Math.max(4, maxCol + 1.4), show: false },
      yAxis: { type: "value", min: -0.2, max: Math.max(2, maxRow + 1.2), inverse: true, show: false },
      series: [
        {
          type: "custom",
          renderItem: (params, api) => {
            const cell = displayCells[params.dataIndex];
            if (!cell) return null;
            const xUnit = cell.col + (cell.row % 2 === 1 ? 0.5 : 0) + 0.55;
            const yUnit = cell.row + 0.55;
            const center = api.coord([xUnit, yUnit]);
            const nextCol = api.coord([xUnit + 1, yUnit]);
            const spacingPx = Math.max(24, nextCol[0] - center[0]);
            const radius = Math.min(30, spacingPx * 0.43);

            const outerPts = hexPolygon(center[0], center[1], radius);
            if (cell.status === "empty") {
              return {
                type: "polygon",
                silent: true,
                shape: { points: outerPts },
                style: {
                  fill: hexEmpty,
                  stroke: hexEmptyStroke,
                  lineWidth: 1,
                  lineDash: [3, 3],
                },
              };
            }

            const innerPts = hexPolygon(center[0], center[1], radius * 0.72);
            const palette = hexColors(cell.status);
            const isSelected = Boolean(cell.deviceId && cell.deviceId === selectedDeviceId);
            const fillGrad = new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: palette.start },
              { offset: 1, color: palette.end },
            ]);

            type CustomChild = NonNullable<echarts.CustomSeriesRenderItemReturn>;
            const children: CustomChild[] = [
              {
                type: "polygon",
                shape: { points: outerPts },
                style: {
                  fill: fillGrad,
                  opacity: 0.9,
                  stroke: isSelected ? inkPrimary : palette.edge,
                  lineWidth: isSelected ? 2.4 : 1.5,
                  shadowBlur: isSelected ? 14 : 8,
                  shadowColor: palette.glow,
                },
              },
              {
                type: "polygon",
                silent: true,
                shape: { points: innerPts },
                style: {
                  fill: "transparent",
                  stroke: specular,
                  lineWidth: 1,
                },
              },
              {
                type: "circle",
                silent: true,
                shape: { cx: center[0], cy: center[1], r: 2.5 },
                style: { fill: bgCanvas },
              },
            ];

            if (cell.status === "partial" || cell.status === "blind") {
              const hr = radius * 0.46;
              for (const offset of [-hr * 0.5, 0, hr * 0.5]) {
                children.push({
                  type: "line",
                  silent: true,
                  shape: {
                    x1: center[0] + offset - hr * 0.45,
                    y1: center[1] + hr * 0.45,
                    x2: center[0] + offset + hr * 0.45,
                    y2: center[1] - hr * 0.45,
                  },
                  style: { stroke: decalInk, lineWidth: 1.4 },
                });
              }
            }

            return {
              type: "group",
              children,
            };
          },
          data: displayCells.map((c, idx) => [c.col, c.row, idx]),
        },
      ],
    };
  }, [displayCells, maxCol, maxRow, selectedDeviceId, themeTick]);

  return (
    <GrdrChart
      option={option}
      width="100%"
      height={height}
      ariaLabel="Interactive honeycomb hexbin map of fleet endpoints"
      onPointClick={(idx) => {
        const cell = displayCells[idx];
        if (cell?.deviceId) onSelectDevice(cell.deviceId);
      }}
    />
  );
}
