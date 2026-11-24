import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { OperatorApp } from "./OperatorApp";

const rootEl = document.getElementById("root");
if (rootEl) {
  createRoot(rootEl).render(
    <StrictMode>
      <OperatorApp />
    </StrictMode>,
  );
}
