import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";

// Shared primitives following style-guide.md: 8px radius buttons at 36px,
// 12px radius cards, hairline borders, no shadows.

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

const buttonStyles: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-hover",
  secondary: "border border-border text-text hover:bg-surface-2",
  ghost: "text-muted hover:bg-surface-2 hover:text-text",
  danger: "border border-critical/40 text-critical hover:bg-critical/10",
};

export function Button({
  variant = "secondary",
  size = "md",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: "sm" | "md" }) {
  return (
    <button
      type="button"
      {...props}
      className={[
        "inline-flex items-center justify-center gap-2 rounded-lg px-3 text-[14px] font-medium transition-colors duration-150 disabled:pointer-events-none disabled:opacity-50",
        size === "sm" ? "h-8" : "h-9",
        buttonStyles[variant],
        className,
      ].join(" ")}
    />
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-xl border border-border bg-surface p-6 ${className}`}>{children}</div>;
}

export function Input({ className = "", ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`h-9 w-full rounded-lg border border-border bg-bg px-3 text-[14px] text-text placeholder:text-subtle transition-colors duration-150 focus:border-border-strong ${className}`}
    />
  );
}

export function Label({ children, htmlFor }: { children: ReactNode; htmlFor: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-2 block text-[13px] font-medium text-muted">
      {children}
    </label>
  );
}

export function PageTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-8 flex items-center justify-between gap-4">
      <h1 className="text-[28px] font-semibold tracking-[-0.02em]">{children}</h1>
      {action}
    </div>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className="inline-block animate-spin rounded-full border-2 border-border border-t-accent"
      style={{ width: size, height: size }}
    />
  );
}
