# IronVeil Dashboard

The web dashboard for IronVeil database proxy. Built with Next.js 16, React 19, Tailwind CSS 4, and a comprehensive UI component library.

## Features

- **Dashboard**: Real-time system status with live charts, connection graphs, and masking statistics
- **Masking Rules**: View, add, test, and manage data masking rules with live preview
- **Rule Testing**: Preview illustrative masking output per strategy before saving (actual masking happens server-side)
- **PII Scanner**: Scan database for potential PII columns with editable connection settings and one-click rule creation
- **Live Inspector**: Real-time query monitoring with masked data details
- **Settings**: Global masking controls, theme selection, and configuration export
- **Theme Support**: Dark, light, and system themes with persistent preference

## Getting Started

### Prerequisites

- Node.js 20.9+ (required by Next.js 16; enforced via the `engines` field in `package.json`)
- The IronVeil proxy running on port 3001 (API)

### Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

### Production Build

```bash
npm run build
npm start
```

## Tech Stack

- **Framework**: Next.js 16 (App Router)
- **React**: React 19
- **Styling**: Tailwind CSS 4
- **UI Components**: Custom component library (Button, Dialog, Tabs, Switch, Badge, etc.)
- **State Management**: TanStack Query 5 (React Query)
- **Charts**: Recharts
- **Animations**: Framer Motion
- **Themes**: next-themes
- **Icons**: Lucide React

## Project Structure

```
web/
├── public/
│   └── logo.png           # IronVeil logo
├── src/
│   ├── app/
│   │   ├── layout.tsx     # Root layout with sidebar
│   │   ├── page.tsx       # Dashboard with charts
│   │   ├── globals.css    # Global styles & theme variables
│   │   ├── inspector/     # Live query inspector
│   │   ├── rules/         # Masking rules with test dialog
│   │   ├── scan/          # PII scanner
│   │   └── settings/      # Settings with theme toggle
│   ├── components/
│   │   ├── sidebar.tsx    # Navigation sidebar
│   │   ├── providers.tsx  # React Query + Theme providers
│   │   ├── theme-provider.tsx  # next-themes wrapper
│   │   ├── theme-toggle.tsx    # Theme selection component
│   │   ├── stats-card.tsx      # Metric display card
│   │   ├── rule-test-dialog.tsx # Rule testing dialog
│   │   ├── charts/        # Chart components
│   │   │   ├── connections-chart.tsx
│   │   │   ├── masking-stats-chart.tsx
│   │   │   └── query-types-chart.tsx
│   │   └── ui/            # UI component library
│   │       ├── button.tsx
│   │       ├── dialog.tsx
│   │       ├── tabs.tsx
│   │       ├── switch.tsx
│   │       ├── badge.tsx
│   │       ├── input.tsx
│   │       ├── select.tsx
│   │       ├── label.tsx
│   │       ├── tooltip.tsx
│   │       └── card.tsx
│   └── lib/
│       ├── api.ts         # API client (auth, timeouts, error handling)
│       ├── query.ts       # Shared TanStack Query polling/retry policies
│       ├── masking-preview.ts # Illustrative strategy previews
│       └── utils.ts       # Utility functions (cn)
├── package.json
└── next.config.ts
```

## UI Components

The dashboard includes a comprehensive UI component library:

| Component | Description |
|-----------|-------------|
| `Button` | Configurable button with variants (default, success, warning, destructive, etc.) |
| `Dialog` | Modal dialog with Radix UI primitives |
| `Tabs` | Tabbed content navigation |
| `Switch` | Toggle switch for boolean settings |
| `Badge` | Status indicators and labels |
| `Input` | Form text input |
| `Select` | Dropdown selection |
| `Tooltip` | Hover information tooltips |
| `Card` | Content container with header/content sections |
| `StatsCard` | Metric display with icon and trend indicator |

## Charts

Real-time data visualization using Recharts:

- **ConnectionsChart**: Area chart showing connections over time
- **MultiLineChart**: Multi-series chart for queries and masked fields
- **MaskingStatsChart**: Horizontal bar chart for masking operations by strategy
- **QueryTypesChart**: Pie chart for query type distribution

## API Endpoints

The dashboard connects to the IronVeil Management API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check with upstream status |
| `/rules` | GET | List masking rules (`{ "rules": [...] }`) |
| `/rules` | POST | Add or update a masking rule (upsert by `table`+`column`) |
| `/rules/delete` | POST | Delete a rule by `{ "table": ..., "column": ... }` |
| `/rules/export` | GET | Export the rules array (restorable via `/rules/import`) |
| `/rules/import` | POST | Import a bare rules array |
| `/config` | GET | Get config summary (`masking_enabled`, `rules_count`) |
| `/config` | POST | Update configuration |
| `/stats` | GET | Get dashboard statistics (connections, queries, masking, history) |
| `/connections` | GET | Get active connection count |
| `/logs` | GET | Get recent query logs |
| `/scan` | POST | Trigger PII scan (requires DB credential payload; PostgreSQL scanner currently) |
| `/schema` | POST | Get database schema (requires DB credential payload; PostgreSQL scanner currently) |
| `/audit` | GET | Get audit logs |

`GET /health` includes upstream runtime metadata consumed by the settings/dashboard UI:

```json
{
  "status": "ok",
  "version": "0.2.0",
  "upstream": {
    "host": "localhost",
    "port": 5432,
    "protocol": "postgres",
    "healthy": true
  }
}
```

### Scan/Schema Payload

```json
{
  "username": "<db-username>",
  "password": "<db-password>",
  "database": "postgres",
  "schema": "public",
  "sample_size": 100,
  "confidence_threshold": 0.5,
  "exclude_tables": []
}
```

The scanner form does not pre-fill credentials; both username and password must be
entered before a scan can be started.

`POST /scan` and `POST /schema` can return:

- `401 Unauthorized` (`auth_required`) when `username` or `password` is missing/blank.
- `501 Not Implemented` (`unsupported_protocol`) when IronVeil runs with `--protocol mysql`.
- `502 Bad Gateway` (`connection_failed`) when upstream DB connection fails.
- `500 Internal Server Error` (`query_failed`) when schema/query execution fails after connection.

Rule behavior:

- Rule targets are unique by `(table, column)` (case-insensitive).
- Adding a rule for an existing target updates its strategy instead of creating duplicates.
- Import also deduplicates duplicate targets.

## Rule Matching Notes

- MySQL runtime masking supports table-scoped rules (`table` + `column`).
- PostgreSQL runtime masking resolves table OIDs at session bootstrap and applies table-scoped rules (`table` + `column`).
- If PostgreSQL OID resolution fails, runtime behavior falls back to global column rules for safety.

## Development

```bash
# Run linter
npm run lint

# Type check
npx tsc --noEmit

# Build for production
npm run build
```

## API Configuration

The dashboard uses this optional client-side setting:

- `NEXT_PUBLIC_API_BASE_URL`: Override API origin (default: `http://localhost:3001`)

Credentials are never configured through `NEXT_PUBLIC_*` environment variables:
those values are inlined into the public JavaScript bundle at build time and would
leak to anyone who can load the dashboard.

API authentication is configured at runtime from the Settings page **API
Authentication** panel. You pick exactly one auth mode (`None`, `API Key`, or
`Bearer Token`) and enter the matching credential; the client then sends exactly
one of `X-API-Key` or `Authorization: Bearer ...` per request, never both. The
credential is kept in `sessionStorage` (keys `ironveil.auth_mode` and
`ironveil.auth_credential`), so it is cleared when the tab closes, and the panel
includes a **Clear Credentials** action to remove it immediately.

Frontend API behavior:

- The shared client (`web/src/lib/api.ts`) throws an `ApiError` for non-2xx responses.
- `ApiError` includes `status`, `code` (if present), `endpoint`, and parsed error payload.
- Requests are aborted after 15 seconds via `AbortController` so hangs surface as errors.
- `/health` is special-cased: a 503 "degraded" body is returned as data instead of thrown,
  so the UI can distinguish "upstream degraded" from "API unreachable".
- Pages poll via TanStack Query with shared policies (`web/src/lib/query.ts`): polling
  stops on 401, backs off on 5xx/network errors, and pauses in background tabs.
- All pages surface fetch failures in visible `role="alert"` banners (scanner errors such
  as `auth_required` included) rather than silently rendering empty state.

## Screenshots

### Dashboard
Real-time monitoring with connection charts, masking statistics, and activity feed.

### Rules Management  
Create, test, and manage masking rules with live preview functionality.

### Settings
Configure themes, global masking toggle (with confirmation before disabling), API
authentication, and rules export (`ironveil-rules.json`, restorable via `/rules/import`).
