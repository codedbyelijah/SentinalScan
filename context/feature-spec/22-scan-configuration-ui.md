Read `AGENTS.md`, `context/ui-context.md`, `context/code-standards.md`, and `context/progress-tracker.md` before starting.

We're building the user interface for configuring scans.

Install the latest version.

```bash
pnpm add react-hook-form zod @hookform/resolvers
```

Create:

- `frontend/components/dashboard/scan-configuration.tsx`

Dependencies:

- Dashboard Layout
- Shared API client

Requirements:

- Target input.
- Scan mode selection.
- Module selection.
- Schedule configuration.
- Form validation.
- Submit button.
- Loading state.

Do not:

- Execute scans.
- Display scan progress.
- Display scan results.

Update:

- `context/progress-tracker.md`

Mark this feature as completed after successful implementation.

### Check when done

- Form validation works.
- Scan configuration submits correctly.
- Loading state is displayed.
- No TypeScript errors.
- No lint errors.
