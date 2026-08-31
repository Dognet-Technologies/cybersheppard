# CyberSheppard MicroSIEM UI — conventions

A React + Tailwind component kit for security-monitoring interfaces (alerts, hosts,
auditd events, compliance, hardening). Components are self-contained and style themselves
with Tailwind utility classes on the **default Tailwind palette** — blue = primary,
red = danger, green = success, yellow = warning, gray = neutral. There are no custom
design tokens.

## Setup — no provider required
Import components and render them directly. There is **no** ThemeProvider, context, or root
wrapper — every component works standalone. Styling comes entirely from the bundled
stylesheet (`styles.css`, which `@import`s the compiled Tailwind CSS). Icon props (`icon`)
take any React node; the kit itself uses `lucide-react` icons.

## Styling idiom
- Components carry their own Tailwind styling — do not restyle them with conflicting classes.
- Every component accepts `className` (merged with clsx) to extend or position it.
- For your own layout glue around components, use standard Tailwind utilities on the default
  scale: spacing (`gap-3`, `p-6`, `space-y-3`), flex/grid (`flex items-center`,
  `grid grid-cols-4`), color (`text-gray-500`, `bg-gray-50`, `text-gray-900`). No custom
  token names exist — use plain Tailwind classes only.
- Semantic variants carry meaning; use them consistently:
  - `Button` — `variant`: `primary | secondary | danger | ghost | outline`; `size`: `sm | md | lg`;
    also `icon`, `iconPosition` (`left | right`), `loading`, `fullWidth`.
  - `Badge` — `variant`: `success | warning | danger | info | default`; `size`: `sm | md | lg`.
  - `SeverityBadge` — `severity`: `critical | high | medium | low | info` (maps to a color).
  - `StatusBadge` — `status`: `online | offline | active | inactive | new | acknowledged | resolved`.
  - `StatCard` — `variant`: `default | success | warning | danger | info`; plus `icon`,
    `subtitle`, and `trend` ({ value, label }). Wrap several in `StatsGrid` (`columns`: 2 | 3 | 4).
  - `Card` — compose with `CardHeader` ({ title, subtitle, action }) and `CardSection`
    ({ border }); `padding`: `none | sm | md | lg`; `hover`.
  - `Table` — pass `data` + `columns` ({ key, label, sortable?, render? }); has `loading` and
    `emptyMessage` states. Render badges inside cells via a column `render`.
  - `Input` (extends native input; optional leading `icon`) and `Select` (extends native
    select) for forms.

## Where the truth lives
- `styles.css` → `@import`s `_ds_bundle.css` (the compiled Tailwind) — read it for the exact
  utility classes available.
- Each component's `<Name>.d.ts` is the authoritative prop contract; `<Name>.prompt.md`
  shows usage.

## Idiomatic example
```tsx
import { StatsGrid, StatCard, Badge, Button, Card, CardHeader } from 'cybersheppard-frontend';

<div className="space-y-6">
  <StatsGrid columns={3}>
    <StatCard title="Active Alerts" value={7} variant="danger" subtitle="2 critical, 5 high" />
    <StatCard title="Hosts Online" value="12 / 13" variant="success" />
    <StatCard title="Compliance" value="86%" variant="info" />
  </StatsGrid>

  <Card>
    <CardHeader title="web-prod-01" subtitle="Ubuntu 22.04 · 192.168.10.21"
      action={<Badge variant="success">Online</Badge>} />
    <div className="flex items-center justify-end gap-2">
      <Button variant="ghost">Dismiss</Button>
      <Button variant="danger">Quarantine</Button>
    </div>
  </Card>
</div>
```
