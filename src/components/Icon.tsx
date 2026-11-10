import type { ReactNode } from 'react';

const PATHS = {
  overview: (
    <path d="M2.5 2.5h4.5v4.5H2.5zM9 2.5h4.5v4.5H9zM2.5 9h4.5v4.5H2.5zM9 9h4.5v4.5H9z" />
  ),
  threatIntel: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <circle cx="8" cy="8" r="1.5" />
      <path d="M8 1v3M8 12v3M1 8h3M12 8h3" />
    </>
  ),
  vulnerabilities: <path d="M8 2.2 14 13H2zM8 6.5v3M8 11.2v.3" />,
  soc: <path d="M2.5 3.5h11v9h-11zM5 6.5 7 8 5 9.5M8.5 10H11" />,
  attack: <path d="M3 3v10M6.3 3v7M9.7 3v10M13 3v5" />,
  toolbox: (
    <>
      <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
      <circle cx="5.5" cy="4.5" r="1.3" fill="currentColor" />
      <circle cx="10.5" cy="8" r="1.3" fill="currentColor" />
      <circle cx="7" cy="11.5" r="1.3" fill="currentColor" />
    </>
  ),
  lab: <path d="M6 2.5h4M6.8 2.5v4l-3.6 6.1a.8.8 0 0 0 .7 1.2h8.2a.8.8 0 0 0 .7-1.2L9.2 6.5v-4M5 10.5h6" />,
  settings: (
    <>
      <circle cx="8" cy="8" r="2.2" />
      <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4" />
    </>
  ),
  menu: <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />,
  close: <path d="m3.5 3.5 9 9M12.5 3.5l-9 9" />,
  arrow: <path d="M3 8h10M9 4l4 4-4 4" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

/** Decorative 16px stroke icon. Always paired with visible or accessible text. */
export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg
      viewBox="0 0 16 16"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={className}
    >
      {PATHS[name]}
    </svg>
  );
}
