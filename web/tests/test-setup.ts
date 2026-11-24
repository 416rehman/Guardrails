import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  window.matchMedia = (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}

if (typeof HTMLDialogElement !== "undefined") {
  if (!HTMLDialogElement.prototype.showModal) {
    HTMLDialogElement.prototype.showModal = function showModal() {
      this.setAttribute("open", "");
    };
  }
  if (!HTMLDialogElement.prototype.close) {
    HTMLDialogElement.prototype.close = function close() {
      this.removeAttribute("open");
    };
  }
}

if (typeof globalThis.CSS === "undefined" || typeof globalThis.CSS.escape !== "function" || typeof globalThis.CSS.supports !== "function") {
  globalThis.CSS = {
    ...(globalThis.CSS ?? {}),
    escape:
      typeof globalThis.CSS?.escape === "function"
        ? globalThis.CSS.escape
        : (value: string) => String(value).replace(/([^\w-])/g, "\\$1"),
    supports:
      typeof globalThis.CSS?.supports === "function"
        ? globalThis.CSS.supports
        : () => false,
  } as typeof CSS;
}

if (typeof Element !== "undefined" && !Element.prototype.getAnimations) {
  Element.prototype.getAnimations = () => [];
}

if (typeof window !== "undefined") {
  window.scrollTo = () => {};
}

afterEach(() => {
  cleanup();
});
