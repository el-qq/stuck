import React from "react";
import { createRoot } from "react-dom/client";
import App from "@/App";
import { Providers } from "@/Providers";
import "@/styles/globals.css";

const root = document.getElementById("app-root");
if (!root) throw new Error("Application root element was not found");

createRoot(root).render(
  <React.StrictMode>
    <Providers>
      <App />
    </Providers>
  </React.StrictMode>,
);
