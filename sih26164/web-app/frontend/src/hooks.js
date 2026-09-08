import { useCallback, useEffect, useState } from "react";
import { currentRoute, navigate } from "./lib/router.js";

/** Tracks the current hash route; scrolls to top and moves focus to main. */
export function useHashRoute() {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const onChange = () => {
      setRoute(currentRoute());
      document.getElementById("main")?.focus?.({ preventScroll: true });
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const go = useCallback((name, param) => navigate(name, param), []);
  return [route, go];
}
