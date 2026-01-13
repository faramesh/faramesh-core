# FaraCore UI

Modern React + TypeScript + Tailwind CSS UI for FaraCore.

## Development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

This will build the app to `../src/faracore/web/` which is served by the FastAPI backend.

## Structure

- `src/App.tsx` - Main app component
- `src/components/` - React components
- `src/hooks/` - Custom React hooks
- `src/types.ts` - TypeScript types

## Features

- Real-time updates via SSE
- Dark/light mode toggle
- Action filtering and search
- Pagination (25 per page)
- Status highlighting
- Action details drawer
- Toast notifications
