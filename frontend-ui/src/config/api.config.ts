export const API_CONFIG = {
  BASE_URL: process.env.REACT_APP_API_BASE_URL || 'http://localhost:8080/api',
  ML_SERVICE_URL: process.env.REACT_APP_ML_SERVICE_URL || 'http://localhost:8000',
  MAX_FILE_SIZE: parseInt(process.env.REACT_APP_MAX_FILE_SIZE || '10485760'), // 10MB
  TIMEOUT: 30000, // 30 seconds
};

export const API_ENDPOINTS = {
  // Auth endpoints
  LOGIN: '/auth/login',
  REGISTER: '/auth/register',
  LOGOUT: '/auth/logout',
  REFRESH_TOKEN: '/auth/refresh',
  
  // Contract/Scan endpoints (backend uses /contracts prefix)
  UPLOAD_CONTRACT: '/contracts/upload',
  SCAN_STATUS: '/contracts/scan/:id/status',
  SCAN_RESULTS: '/contracts/scan/:id/results',
  SCAN_HISTORY: '/contracts/scans',
  
  // Report endpoints
  DOWNLOAD_PDF: '/contracts/scan/:id/report',
  SHARE_REPORT: '/contracts/scan/:id/report/generate',
  
  // User endpoints
  USER_PROFILE: '/users/profile',
  USER_STATS: '/users/stats',
};

export const SUPPORTED_FILE_TYPES = {
  SOLIDITY: ['.sol'],
  MOVE: ['.move'],
};

export const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
} as const;

export const SCAN_STATUS = {
  PENDING: 'pending',
  UPLOADING: 'uploading',
  ANALYZING: 'analyzing',
  COMPLETED: 'completed',
  FAILED: 'failed',
} as const;
