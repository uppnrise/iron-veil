# IronVeil Dashboard

The web dashboard for IronVeil database proxy. Built with Next.js 16, React 19, Tailwind CSS 4, and a comprehensive UI component library.

## Features

- **Dashboard**: Real-time system status with live charts, connection graphs, and masking statistics
- **Masking Rules**: View, add, test, and manage data masking rules with live preview
- **Rule Testing**: Test masking strategies with sample data before saving
- **PII Scanner**: Scan database for potential PII columns with one-click rule creation
- **Live Inspector**: Real-time query monitoring with masked data details
- **Settings**: Global masking controls, theme selection, and configuration export
- **Theme Support**: Dark, light, and system themes with persistent preference

## Getting Started

### Prerequisites

- Node.js 18+
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
│       └── utils.ts       # Utility functions (cn, formatBytes, etc.)
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
| `/rules` | GET | List all masking rules |
| `/rules` | POST | Add a new masking rule |
| `/rules/delete` | POST | Delete a rule by index or column |
| `/config` | GET | Get current configuration |
| `/config` | POST | Update configuration |
| `/connections` | GET | Get active connection count |
| `/logs` | GET | Get recent query logs |
| `/scan` | POST | Trigger PII scan |
| `/schema` | POST | Get database schema |
| `/audit` | GET | Get audit logs |

## Development

```bash
# Run linter
npm run lint

# Type check
npx tsc --noEmit

# Build for production
npm run build
```

## Screenshots

### Dashboard
Real-time monitoring with connection charts, masking statistics, and activity feed.

### Rules Management  
Create, test, and manage masking rules with live preview functionality.

### Settings
Configure themes, global masking toggle, and export configuration.
