import { useState } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import "@grdr/tokens/tokens.css";
import "./styles.css";
import { createOperatorQueryClient } from "./queries";
import { createOperatorRouter } from "./router";

export function OperatorApp() {
  const [queryClient] = useState(() => createOperatorQueryClient());
  const [router] = useState(() => createOperatorRouter());

  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
