// Apply persisted appearance before React mounts to avoid a theme flash.
try {
  let theme = localStorage.getItem("stuck.theme");
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
  const accent = localStorage.getItem("stuck.accent");
  if (accent) document.documentElement.style.setProperty("--accent", accent);
} catch {
  // Storage can be unavailable in hardened/private browser contexts.
}
