import type { SVGProps } from "react";

/** The SealedRun mark: a ring with one gap, closed by the seal dot. Ring follows `currentColor`. */
export function Logo({ size = 20, ...props }: SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden {...props}>
      <path
        d="M24 5a19 19 0 1 1-13.4 5.6"
        fill="none"
        stroke="currentColor"
        strokeWidth="5"
        strokeLinecap="round"
      />
      <circle cx="10" cy="11" r="5.5" className="fill-seal" />
    </svg>
  );
}
