# FaraCore UI Setup

## Prerequisites

- Node.js 18+ and npm

## Installation

```bash
cd web
npm install
```

## Development

```bash
npm run dev
```

This starts a Vite dev server. Note: You'll need to configure the API base URL in the browser console or update `index.html` if running separately from the FastAPI backend.

## Building for Production

```bash
npm run build
```

This builds the React app to `../src/faracore/web/`, which is served by FastAPI at `/app/`.

## Logo

Place `logo.png` in the `public/` directory. It will be available at `/app/logo.png` when built.

## Features Implemented

✅ Fixed top nav bar with logo and theme toggle
✅ Action table with status highlighting
✅ Truncated IDs (8 chars) with copy on hover
✅ Action details drawer/panel
✅ Real-time SSE updates with live indicator
✅ Policy info banner
✅ Pagination (25 per page)
✅ Search with "/" keyboard shortcut
✅ Toast notifications
✅ Dark/light mode
✅ Status badges with proper colors
✅ Approve/Deny buttons in details panel

## Component Structure

- `components/NavBar.tsx` - Top navigation
- `components/ActionTable.tsx` - Main actions table
- `components/ActionDetails.tsx` - Right-side drawer
- `components/StatusBadge.tsx` - Status indicators
- `components/Toast.tsx` - Notifications
- `components/PolicyBanner.tsx` - Policy info banner
- `hooks/useSSE.ts` - SSE connection hook
- `hooks/useActions.ts` - Actions data management

## Status Colors

- `pending_approval` - Yellow
- `approved` - Blue
- `allowed` - Green
- `denied` - Red
- `executing` - Purple (with pulse animation)
- `succeeded` - Green
- `failed` - Red
