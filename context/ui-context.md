# UI Context

## Theme

SentinelScan uses a dark-only interface inspired by modern cybersecurity dashboards. The design emphasizes clarity, focus, and readability through layered dark surfaces, subtle borders, and accent colors that communicate system state. Green indicates successful operations, blue represents primary actions and navigation, yellow highlights warnings or running processes, and red indicates errors or critical findings.

## Colors

All colors must be defined as CSS custom properties. Components should reference these variables rather than hardcoded color values.

| Role            | CSS Variable       | Value     |
| --------------- | ------------------ | --------- |
| Page background | `--bg-base`        | `#0B1220` |
| Surface         | `--bg-surface`     | `#111827` |
| Primary text    | `--text-primary`   | `#F9FAFB` |
| Muted text      | `--text-muted`     | `#9CA3AF` |
| Primary accent  | `--accent-primary` | `#2563EB` |
| Border          | `--border-default` | `#374151` |
| Error           | `--state-error`    | `#DC2626` |
| Success         | `--state-success`  | `#16A34A` |

## Typography

| Role      | Font       | Variable      |
| --------- | ---------- | ------------- |
| UI text   | Geist Sans | `--font-sans` |
| Code/mono | Geist Mono | `--font-mono` |

## Border Radius

| Context           | Class         |
| ----------------- | ------------- |
| Inline / small UI | `rounded-md`  |
| Cards / panels    | `rounded-xl`  |
| Modals / overlays | `rounded-2xl` |

## Component Library

Use **shadcn/ui** built on top of Tailwind CSS. Components should reside in `components/ui/`, with new components added through the shadcn CLI whenever possible. Prefer composition of existing components instead of creating custom UI elements from scratch.

## Layout Patterns

- Dashboard: top navigation bar with a main content area for scan configuration, progress, and reports.
- Forms: centered content with responsive card layouts and clear section spacing.
- Progress View: progress indicator at the top with expandable sections showing the status of each scanning module.
- Report View: summary cards followed by detailed findings grouped by scan module.
- Dialogs: centered modal with backdrop blur for confirmations and error messages.

## Icons

Use **Lucide React** throughout the application. Prefer stroke-based icons only. Use `h-4 w-4` for inline icons, `h-5 w-5` for buttons, and `h-6 w-6` for section headers or dashboard cards.
