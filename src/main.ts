import { mount } from "svelte";
import App from "./App.svelte";

// Placeholder UI entry point. The whole UI layer (this file + App.svelte
// and future components) is deliberately thin and disposable: all state
// and logic live in the Rust core / stores, so the UI can be replaced
// wholesale when the real design arrives. See docs/DESIGN.md.
const app = mount(App, {
  target: document.getElementById("app")!,
});

export default app;
