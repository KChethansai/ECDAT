import React from "react";

/* Local stroke icon set (no dependency). 24-viewBox, currentColor. */
function I({ children, size = 14, width = 1.8 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" focusable="false">
      <g stroke="currentColor" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round">
        {children}
      </g>
    </svg>
  );
}

export const IconShield = (p) => (
  <I {...p}>
    <path d="M12 2.8 19.5 6v5.7c0 4.6-3.1 7.6-7.5 8.8-4.4-1.2-7.5-4.2-7.5-8.8V6L12 2.8Z" />
    <path d="m8.9 11.8 2.2 2.2 4-4.4" />
  </I>
);
export const IconScan = (p) => (
  <I {...p}>
    <path d="M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8" />
    <path d="M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8" />
    <path d="M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16" />
    <path d="M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16" />
    <path d="M4 12h16" />
  </I>
);
export const IconEvidence = (p) => (
  <I {...p}>
    <ellipse cx="12" cy="5.5" rx="7.5" ry="2.5" />
    <path d="M4.5 5.5v13c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5v-13" />
    <path d="M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5" />
  </I>
);
export const IconGauge = (p) => (
  <I {...p}>
    <path d="M4 14a8 8 0 1 1 16 0" />
    <path d="M12 14l4-4.5" />
    <path d="M4 17.5h16" />
  </I>
);
export const IconFlag = (p) => (
  <I {...p}>
    <path d="M5 21V4" />
    <path d="M5 4.5h12.5l-2.5 4 2.5 4H5" />
  </I>
);
export const IconCompass = (p) => (
  <I {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="m15.5 8.5-2 5-5 2 2-5 5-2Z" />
  </I>
);
export const IconMigrate = (p) => (
  <I {...p}>
    <path d="M4 7h13l-3-3" />
    <path d="M20 17H7l3 3" />
  </I>
);
export const IconBox = (p) => (
  <I {...p}>
    <path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z" />
    <path d="M4.2 7.6 12 12l7.8-4.4" />
    <path d="M12 12v8.7" />
  </I>
);
export const IconSearch = (p) => (
  <I {...p}>
    <circle cx="11" cy="11" r="6.5" />
    <path d="m16 16 4.5 4.5" />
  </I>
);
export const IconX = (p) => (
  <I {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </I>
);
export const IconCheck = (p) => (
  <I {...p}>
    <path d="m5 12.5 4.5 4.5L19 7.5" />
  </I>
);
export const IconAlert = (p) => (
  <I {...p}>
    <path d="M12 3.5 22 20H2L12 3.5Z" />
    <path d="M12 10v4.5" />
    <path d="M12 17.4v.1" />
  </I>
);
export const IconClock = (p) => (
  <I {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 7.5V12l3 2" />
  </I>
);
export const IconLink = (p) => (
  <I {...p}>
    <path d="M10 14a4.2 4.2 0 0 0 6 0l3-3a4.24 4.24 0 0 0-6-6l-1.5 1.5" />
    <path d="M14 10a4.2 4.2 0 0 0-6 0l-3 3a4.24 4.24 0 0 0 6 6L12.5 17.5" />
  </I>
);
export const IconDownload = (p) => (
  <I {...p}>
    <path d="M12 4v11" />
    <path d="m7.5 11.5 4.5 4.5 4.5-4.5" />
    <path d="M4.5 20h15" />
  </I>
);
export const IconEye = (p) => (
  <I {...p}>
    <path d="M2.5 12S6 5.8 12 5.8 21.5 12 21.5 12 18 18.2 12 18.2 2.5 12 2.5 12Z" />
    <circle cx="12" cy="12" r="2.8" />
  </I>
);
export const IconDoc = (p) => (
  <I {...p}>
    <path d="M6 3.5h8L19 8.5V20.5H6V3.5Z" />
    <path d="M13.5 3.5v5.5H19" />
    <path d="M9 13h6M9 16.2h6" />
  </I>
);
export const IconPulse = (p) => (
  <I {...p}>
    <path d="M2.5 12h4l2.5-6 4 12 2.5-6h6" />
  </I>
);
export const IconLock = (p) => (
  <I {...p}>
    <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
    <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
  </I>
);
