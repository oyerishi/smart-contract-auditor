# Frontend UI - Smart Contract Security Auditor

A React-based frontend application for the Smart Contract Security Auditor platform.

## Tech Stack

- **React** 19.2.0
- **TypeScript** 4.9.5
- **React Router** 7.9.6
- **Redux Toolkit** 2.11.0
- **Axios** 1.13.2
- **Monaco Editor** 4.7.0
- **Tailwind CSS**

## Prerequisites

- Node.js (v18 or higher recommended)
- npm or yarn

## Installation

```bash
# Navigate to frontend directory
cd frontend-ui

# Install dependencies
npm install
```

## Commands

| Command | Description |
|---------|-------------|
| `npm start` | Start development server on http://localhost:3000 |
| `npm run build` | Build production bundle to `build/` folder |
| `npm test` | Run test suite |
| `npm run eject` | Eject from Create React App (irreversible) |

## Running the Application

### Development Mode

```bash
npm start
```

The application will start on `http://localhost:3000` and automatically open in your browser.

### Production Build

```bash
npm run build
```

The optimized production build will be created in the `build/` directory.

## Project Structure

```
frontend-ui/
├── public/                     # Static assets
│   ├── index.html              # HTML template
│   ├── manifest.json           # PWA manifest
│   └── robots.txt              # SEO robots file
├── src/
│   ├── components/             # Reusable UI components
│   │   ├── common/             # Shared components (buttons, inputs, etc.)
│   │   ├── dashboard/          # Dashboard-specific components
│   │   ├── editor/             # Code editor components
│   │   └── upload/             # File upload components
│   ├── config/                 # Configuration files
│   │   ├── api.config.ts       # API endpoint configuration
│   │   └── constants.ts        # App constants
│   ├── context/                # React Context providers
│   │   ├── AuthContext.tsx     # Authentication context
│   │   └── ScanContext.tsx     # Scan state context
│   ├── hooks/                  # Custom React hooks
│   │   ├── useAuth.ts          # Authentication hook
│   │   └── useScanPolling.ts   # Scan status polling hook
│   ├── pages/                  # Page components
│   │   ├── Dashboard.tsx       # Main dashboard page
│   │   ├── Home.tsx            # Landing page
│   │   ├── Login.tsx           # Login page
│   │   ├── Register.tsx        # Registration page
│   │   └── ScanReport.tsx      # Scan results page
│   ├── services/               # API service layer
│   │   ├── apiClient.ts        # Axios HTTP client
│   │   ├── authService.ts      # Authentication API calls
│   │   ├── fileService.ts      # File upload API calls
│   │   └── scanService.ts      # Scan-related API calls
│   ├── utils/                  # Utility functions
│   │   ├── dateFormat.ts       # Date formatting helpers
│   │   ├── fileUtils.ts        # File handling utilities
│   │   └── riskCalculator.ts   # Risk score calculations
│   ├── App.tsx                 # Root application component
│   ├── App.css                 # Global styles
│   ├── index.tsx               # Application entry point
│   └── index.css               # Base CSS styles
├── build/                      # Production build output
├── package.json                # Dependencies and scripts
├── tailwind.config.js          # Tailwind CSS configuration
├── tsconfig.json               # TypeScript configuration
└── postcss.config.js           # PostCSS configuration
```

## Environment Configuration

Create a `.env` file in the `frontend-ui` directory:

```env
REACT_APP_API_URL=http://localhost:8080/api
```

## Features

- **User Authentication**: Login and registration with JWT tokens
- **Contract Upload**: Upload Solidity smart contracts for analysis
- **Code Editor**: Monaco-based code editor with Solidity syntax highlighting
- **Dashboard**: View all scans and their statuses
- **Scan Reports**: Detailed vulnerability reports with risk scores
- **Real-time Polling**: Automatic status updates for ongoing scans

## API Integration

The frontend connects to the Java backend service running on `http://localhost:8080/api`. Ensure the backend is running before starting the frontend.
