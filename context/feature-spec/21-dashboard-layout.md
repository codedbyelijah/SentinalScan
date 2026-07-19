Read `AGENTS.md`, `context/ui-context.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the primary dashboard layout for SentinelScan.

Install the latest version.

```bash
pnpm add lucide-react
```

Create:

- `frontend/components/dashboard/dashboard-layout.tsx`

Dependencies:

- Existing UI components
- Existing layout components

Requirements:

- Responsive layout.
- Sidebar navigation.
- Top navigation bar.
- Main content area.
- Dark theme.
- Mobile-friendly navigation.
- Reusable layout component.

Do not:

- Display scan results.
- Implement API calls.
- Implement scan configuration.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Dashboard renders correctly.
- Responsive layout works.
- Dark theme is preserved.
- No TypeScript errors.
- No lint errors.
