import "./styles.css";

import { useState } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { createConsoleQueryClient } from "./queries";
import { createConsoleRouter } from "./router";

export function App() {
  const [queryClient] = useState(() => createConsoleQueryClient());
  const [router] = useState(() => createConsoleRouter());

  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

export default App;
