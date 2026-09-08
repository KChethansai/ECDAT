/* Minimal hash router (no dependency): every route works from a fresh load,
   refresh, or bookmark because state lives after '#'. Pure parse() is tested
   with node:test; the hook is a thin hashchange wrapper. */

export const ROUTES = [
  "dashboard", "scan", "findings", "inventory", "risk", "migration",
  "code", "validation", "history", "knowledge", "reports", "settings",
];

export function parseHash(hash) {
  const raw = String(hash || "").replace(/^#\/?/, "");
  const [namePart, param] = raw.split("/");
  const name = ROUTES.includes(namePart) ? namePart : "dashboard";
  const needsParam = name === "findings" || name === "reports" || name === "history";
  return { name, param: needsParam ? decodeURIComponent(param || "") : "" };
}

export function href(name, param = "") {
  return param ? `#/${name}/${encodeURIComponent(param)}` : `#/${name}`;
}

export function currentRoute() {
  if (typeof window === "undefined" || !window.location) return { name: "dashboard", param: "" };
  return parseHash(window.location.hash);
}

export function navigate(name, param = "") {
  if (typeof window === "undefined") return;
  const target = href(name, param);
  if (windowLocationHash() === target) {
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  } else {
    window.location.hash = target;
  }
}

function windowLocationHash() {
  return typeof window === "undefined" ? "" : window.location.hash;
}
