const TRUSTED_KEY = "sealedrun.trusted-principals";

/**
 * The trusted principal list as an external store for `useSyncExternalStore`.
 *
 * The value is remembered in localStorage when it is available; otherwise it lasts until the page
 * is closed. `read` caches the value so that repeated snapshots are stable.
 */
export const trustedStore = (() => {
  const listeners = new Set<() => void>();
  let current: string | null = null;
  return {
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    read: () => {
      if (current === null) {
        try {
          current = localStorage.getItem(TRUSTED_KEY) ?? "";
        } catch {
          current = "";
        }
      }
      return current;
    },
    write: (value: string) => {
      current = value;
      try {
        localStorage.setItem(TRUSTED_KEY, value);
      } catch {}
      listeners.forEach((listener) => listener());
    },
  };
})();
