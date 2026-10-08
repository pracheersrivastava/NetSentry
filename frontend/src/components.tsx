import type { ReactNode } from "react";
import * as Tooltip from "@radix-ui/react-tooltip";
import * as Dialog from "@radix-ui/react-dialog";
import { X, Search, ShieldCheck, ArrowUpRight } from "lucide-react";

export const human = (s: string) =>
  s.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
export const featureName = (name: string) =>
  (
    ({
      pkts_per_sec: "Packet rate",
      bytes_per_sec: "Byte rate",
      unique_dst_ports_5min: "Destination ports (5 min)",
      failed_conn_ratio_5min: "Failed connections (5 min)",
      orig_pkts: "Source packets",
      resp_pkts: "Response packets",
      orig_bytes: "Source bytes",
      resp_bytes: "Response bytes",
      protocol_TCP: "TCP indicator",
      dst_port: "Destination port",
    }) as Record<string, string>
  )[name] ?? human(name);
export function featureValue(name: string, value: number) {
  if (name === "failed_conn_ratio_5min") return `${(value * 100).toFixed(1)}%`;
  const formatted = value.toLocaleString(undefined, {
    maximumFractionDigits: 2,
  });
  return `${formatted}${name === "duration" ? " s" : name === "bytes_per_sec" ? " B/s" : name === "pkts_per_sec" ? " packets/s" : name.endsWith("_bytes") ? " B" : ""}`;
}
export const date = (s: string) =>
  new Date(s.endsWith("Z") || /[+-]\d\d:\d\d$/.test(s) ? s : `${s}Z`);
export const time = (s: string) =>
  date(s).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
export const priority = (score: number) =>
  score >= 0.9
    ? "critical"
    : score >= 0.85
      ? "high"
      : score >= 0.6
        ? "medium"
        : "low";
export function Badge({ value }: { value: string }) {
  return (
    <span className={`badge ${value.toLowerCase()}`}>
      <i />
      {human(value)}
    </span>
  );
}
export function IconButton({
  label,
  onClick,
  children,
  disabled = false,
}: {
  label: string;
  onClick: () => void;
  children: ReactNode;
  disabled?: boolean;
}) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <button
          className="icon-button"
          aria-label={label}
          onClick={onClick}
          disabled={disabled}
        >
          {children}
        </button>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className="tooltip" sideOffset={7}>
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}
export function Panel({
  title,
  meta,
  action,
  children,
  className = "",
}: {
  title: string;
  meta?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {meta && <p>{meta}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Empty({
  title = "No records found",
  text = "",
}: {
  title?: string;
  text?: string;
}) {
  return (
    <div className="empty">
      <ShieldCheck size={30} />
      <h3>{title}</h3>
      {text && <p>{text}</p>}
    </div>
  );
}
export function SearchBox({
  value,
  onChange,
  placeholder = "Search IP, flow or event...",
}: {
  value: string;
  onChange: (s: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="search">
      <Search size={16} />
      <input
        aria-label={placeholder}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {value && (
        <button aria-label="Clear search" onClick={() => onChange("")}>
          <X size={14} />
        </button>
      )}
    </label>
  );
}
export function ScoreGauge({
  score,
  monitor,
  investigate,
}: {
  score: number;
  monitor: number;
  investigate: number;
}) {
  return (
    <div className="score-gauge">
      <div className="score-heading">
        <span>Anomaly score</span>
        <strong className={priority(score)}>
          {score.toFixed(2)}
          <small> / 1.00</small>
        </strong>
      </div>
      <div
        className="gauge-track"
        style={{
          background: `linear-gradient(to right, #3b7770 0% ${monitor * 100}%, #cfa759 ${monitor * 100}% ${investigate * 100}%, #e76e6e ${investigate * 100}% 100%)`,
        }}
      >
        <i style={{ left: `${Math.min(99, Math.max(1, score * 100))}%` }} />
      </div>
      <div className="gauge-labels">
        <span>0.00</span>
        <span style={{ left: `${monitor * 100}%` }}>
          {monitor.toFixed(2)}
          <small>Monitor</small>
        </span>
        <span style={{ left: `${investigate * 100}%` }}>
          {investigate.toFixed(2)}
          <small>Investigate</small>
        </span>
      </div>
    </div>
  );
}
export function Drawer({
  open,
  onClose,
  title,
  description,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={(v) => !v && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="overlay" />
        <Dialog.Content className="drawer">
          <div className="drawer-head">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              <Dialog.Description>{description}</Dialog.Description>
            </div>
            <Dialog.Close className="icon-button" aria-label="Close details">
              <X size={20} />
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
export function TextLink({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="text-link" onClick={onClick}>
      {children}
      <ArrowUpRight size={15} />
    </button>
  );
}
export function download(name: string, data: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
