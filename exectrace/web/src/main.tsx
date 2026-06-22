import React from "react";
import ReactDOM from "react-dom/client";
import "./app.css";
import App from "./App";

// Dark theme is set on <html data-theme="dark"> in index.html; the Upwind
// tokens define the full dark palette under that selector.
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
