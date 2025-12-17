export const APP_CONSTANTS = {
  APP_NAME: 'Smart Contract Security Auditor',
  APP_VERSION: '1.0.0',
  POLL_INTERVAL: 3000, // Poll every 3 seconds for scan status
  MAX_RETRIES: 5, // Maximum retries before giving up
};

export const SEVERITY_LEVELS = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
} as const;

export const MESSAGES = {
  ERROR: {
    GENERIC: 'An error occurred. Please try again.',
    FILE_SIZE: 'File size exceeds the maximum limit.',
    FILE_TYPE: 'Unsupported file type. Please upload .sol or .move files.',
    NETWORK: 'Network error. Please check your connection.',
    UNAUTHORIZED: 'Please login to continue.',
    UPLOAD_FAILED: 'Failed to upload contract. Please try again.',
  },
  SUCCESS: {
    UPLOAD: 'Contract uploaded successfully!',
    SCAN_COMPLETE: 'Analysis completed successfully!',
    LOGIN: 'Login successful!',
    REGISTER: 'Registration successful!',
  },
};

export const RISK_SCORE_THRESHOLDS = {
  CRITICAL: 80,
  HIGH: 60,
  MEDIUM: 40,
  LOW: 20,
};
