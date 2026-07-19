<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes.

Read the relevant documentation in:

node_modules/next/dist/docs/

before implementing anything.

Pay attention to deprecation notices.

<!-- END:nextjs-agent-rules -->

# SentinelScan Frontend Agent

Read `../AGENTS.md` before starting any implementation.

You are responsible only for the Next.js frontend.

## Frontend Rules

- Build only the requested UI.
- Keep components reusable.
- Do not place business logic inside components.
- Use Server Components by default.
- Use Client Components only when required.
- Do not modify backend code.
- Follow the project design system.
- Reuse existing components whenever possible.
