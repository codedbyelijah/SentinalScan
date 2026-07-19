# AI Workflow Rules

## Approach

Build SentinelScan incrementally using a feature-driven, specification-based workflow. Every implementation must follow the project context files (`project-overview.md`, `architecture.md`, `code-standards.md`, `ui-context.md`, and `progress-tracker.md`). Do not invent functionality, modify the system architecture, or introduce new features unless they are defined in the project specifications or explicitly requested.

## Scoping Rules

- Implement one feature or module at a time.
- Complete and verify each feature before starting the next.
- Keep changes small, focused, and easy to review.
- Do not combine unrelated modules into a single implementation.
- Reuse existing components and utilities whenever possible.

## When to Split Work

Split an implementation if it combines:

- Frontend interface changes and backend scanning logic.
- Multiple independent scanning modules (e.g., Reconnaissance and Port Scanning).
- API development and report generation.
- Features whose behavior has not been clearly defined in the project context.

If a feature cannot be implemented and verified independently, divide it into smaller implementation units.

## Handling Missing Requirements

- Do not assume functionality that is not documented.
- If a requirement is ambiguous, resolve it by updating the appropriate context file before implementation.
- If a requirement is missing, record it under **Open Questions** in `progress-tracker.md` before continuing.
- Do not modify the project scope without explicit approval.

## Protected Files

Do not modify the following unless explicitly instructed:

- `components/ui/*` (shadcn/ui generated components)
- Third-party libraries or generated files
- Project context files unless updating documentation to reflect approved implementation changes

## Keeping Docs in Sync

Update the relevant context file whenever implementation changes:

- System architecture or module boundaries
- Technology stack decisions
- Code standards or project conventions
- Feature scope
- User interface conventions
- Project progress and implementation status

## Before Moving to the Next Unit

1. The current feature is fully implemented and functions correctly within its defined scope.
2. The implementation follows all rules defined in `architecture.md` and `code-standards.md`.
3. `progress-tracker.md` has been updated to reflect the completed work.
4. The backend and frontend build successfully without errors.
5. The feature has been tested before beginning the next implementation unit.
