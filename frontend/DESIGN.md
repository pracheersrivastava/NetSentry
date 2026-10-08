# NetSentry Interface Design

Based on the IBM Carbon design analysis from [getdesign.md](https://getdesign.md/ibm/design-md) and adapted for a dark, data-dense security operations console.

## Direction

Use Carbon's precise typography, restrained surfaces, square geometry, and visible hierarchy. This is an operational tool, not a marketing site. Keep the interface quiet so telemetry, thresholds, and analyst decisions carry the emphasis.

## Tokens

- Canvas: `#161616`
- Sidebar: `#262626`
- Raised surface: `#262626`
- Hover surface: `#353535`
- Primary text: `#f4f4f4`
- Secondary text: `#c6c6c6`
- Muted text: `#8d8d8d`
- Divider: `#393939`
- Primary action and focus on dark surfaces: Carbon Blue 40 `#78a9ff`
- Critical: `#da1e28`
- Warning: `#f1c21b`
- Success: `#24a148`

## Typography

- Use locally bundled IBM Plex Sans for all interface text.
- Use weight 300 for page headings, 400 for body copy, and 600 for emphasis.
- Use a system monospace only for IDs, IP addresses, scores, and raw feature values.
- Keep compact operational labels legible. Avoid oversized display text and tracked uppercase decoration.

## Components

- Use flat panels with thin Carbon gray borders and no ambient shadows.
- Keep panels, buttons, fields, and navigation square. Small badges may use a 2px radius.
- Use IBM Blue for primary actions, selected navigation, links, and focus rings.
- Reserve red, yellow, and green for detection severity and service state.
- Make controls direct and compact. Never use pill-shaped command buttons.

## Data and Copy

- Show only values supplied by the API. Label the in-memory sample workspace as demo wherever its data appears.
- Describe the product in concrete terms: network flows, anomaly scores, evidence, investigations, and reports.
- Separate observed telemetry from hypotheses. Do not imply the agent established intent.
- Do not add testimonials, customer logos, adoption claims, promotional counters, decorative photography, or invented operational status.

## Motion and Accessibility

- Use no scroll-triggered or cursor-following effects.
- Keep motion to brief interaction feedback and the functional loading indicator. Respect reduced-motion preferences.
- Preserve keyboard focus, semantic controls, readable contrast, and clear status labels.

## Product Boundaries

- This repository is a self-hosted operations console. Do not add purchase, account, or public marketing terms flows.
- The Privacy page describes the current local browser-to-backend behavior. Review it before any hosted deployment or new telemetry integration.
- The canonical domain is intentionally unset until deployment is planned.
