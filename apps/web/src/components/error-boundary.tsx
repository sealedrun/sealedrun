"use client";

import { Component, type ReactNode } from "react";

/**
 * Keeps a rendering failure inside one section of the page. A record shape the feed did not
 * expect shows a short message in place of the section instead of blanking the whole Inspector.
 */
export class ErrorBoundary extends Component<
  { title: string; children: ReactNode },
  { message: string | null }
> {
  state = { message: null as string | null };

  /** Turns the thrown value into the message shown in place of the section. */
  static getDerivedStateFromError(error: unknown): { message: string } {
    return { message: error instanceof Error ? error.message : String(error) };
  }

  /** The children until one of them throws, then the message. */
  override render(): ReactNode {
    if (this.state.message === null) return this.props.children;
    return (
      <p role="alert" className="rounded-lg border border-bad bg-bad-soft px-4 py-3 text-sm">
        {this.props.title}: {this.state.message}
      </p>
    );
  }
}
