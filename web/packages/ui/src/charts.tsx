import { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts";

export function readToken(name: string, fallback: string): string {
  if (typeof window === "undefined" || typeof document === "undefined") return fallback;
  const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return val || fallback;
}

export function useThemeTick(): string {
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
    const chart = chartRef.current;
    if (!chart) return;
    chart.setOption(option);
    chart.resize();
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
    const fgColor =
      tone === "allow"
        ? readToken("--tone-allow", "rgb(21, 128, 61)")
        : readToken("--accent-primary", "rgb(37, 99, 235)");
    const dialTrack = readToken("--viz-dial-track", "rgb(229, 231, 235)");
    const track = readToken("--border-strong", "rgb(209, 213, 219)");
    const ink = readToken("--ink-primary", "rgb(15, 23, 42)");
    const muted = readToken("--ink-muted", "rgb(100, 116, 139)");
    const bgCanvas = readToken("--bg-canvas", "rgb(255, 255, 255)");
    const sansFont = readToken("--font-sans", "DM Sans, sans-serif");

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
              itemStyle: { color: fgColor },
            },
            splitLine: { show: false },
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
          startAngle: 90,
          endAngle: -270,
          radius: "92%",
          splitNumber: 4,
          axisLine: {
            roundCap: true,
            lineStyle: { width: 6, color: [[1, dialTrack]] },
          },
          progress: {
            show: true,
            roundCap: true,
            width: 6,
            itemStyle: {
              color: fgColor,
            },
          },
          axisTick: { show: false },
          splitLine: { show: false },
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
            offsetCenter: [0, "30%"],
            fontSize: 11.5,
            fontWeight: 500,
            fontFamily: sansFont,
            color: muted,
          },
          data: [{ value: clamped, name: label ?? "Boundary" }],
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
    const allowSolid = readToken("--viz-allow-end", "rgb(59, 130, 246)");
    const askSolid = readToken("--viz-ask-start", "rgb(234, 179, 8)");
    const blockSolid = readToken("--viz-block-start", "rgb(239, 68, 68)");
    const gridLine = readToken("--viz-grid-line", "rgba(15, 23, 42, 0.06)");
    const railTrack = readToken("--viz-rail-track", "rgba(15, 23, 42, 0.03)");
    const inkMuted = readToken("--ink-muted", "rgb(100, 116, 139)");
    const ink = readToken("--ink-primary", "rgb(15, 23, 42)");
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
          barMaxWidth: 20,
          barCategoryGap: "42%",
          data: data.map((d) => ({
            value: d.allowed,
            itemStyle: {
              borderRadius: d.ask === 0 && d.block === 0 ? [3, 3, 2, 2] : [0, 0, 2, 2],
            },
          })),
          itemStyle: {
            color: allowSolid,
            borderWidth: 0,
          },
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
          barMaxWidth: 20,
          data: data.map((d) =>
            d.ask === 0
              ? { value: 0, itemStyle: { borderWidth: 0 } }
              : {
                  value: d.ask,
                  itemStyle: { borderRadius: d.block === 0 ? [3, 3, 0, 0] : [0, 0, 0, 0] },
                },
          ),
          itemStyle: {
            color: askSolid,
            borderWidth: 0,
          },
        },
        {
          name: "Blocked",
          type: "bar",
          stack: "total",
          barMaxWidth: 20,
          data: data.map((d) =>
            d.block === 0 ? { value: 0, itemStyle: { borderWidth: 0 } } : d.block,
          ),
          itemStyle: {
            color: blockSolid,
            borderWidth: 0,
            borderRadius: [3, 3, 0, 0],
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
