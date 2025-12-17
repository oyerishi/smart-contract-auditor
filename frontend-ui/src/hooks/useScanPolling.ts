import { useState, useEffect, useRef } from 'react';
import scanService, { ScanStatus } from '../services/scanService';
import { APP_CONSTANTS } from '../config/constants';

interface UseScanPollingOptions {
  scanId: string | null;
  onComplete?: (scanId: string) => void;
  onError?: (error: string) => void;
  enabled?: boolean;
}

// Maximum polling duration: 5 minutes
const MAX_POLLING_DURATION_MS = 5 * 60 * 1000;

/**
 * Custom hook for polling scan status
 */
export const useScanPolling = ({
  scanId,
  onComplete,
  onError,
  enabled = true,
}: UseScanPollingOptions) => {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const retryCountRef = useRef(0);
  const startTimeRef = useRef<number>(0);

  useEffect(() => {
    if (!scanId || !enabled) {
      return;
    }

    startTimeRef.current = Date.now();

    const stopPolling = () => {
      setIsPolling(false);
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };

    const pollStatus = async () => {
      // Check if we've exceeded max polling duration
      if (Date.now() - startTimeRef.current > MAX_POLLING_DURATION_MS) {
        stopPolling();
        onError?.('Scan timed out. Please check the scan history for results.');
        return;
      }

      try {
        const statusData = await scanService.getScanStatus(scanId);
        setStatus(statusData);

        // Reset retry count on successful poll
        retryCountRef.current = 0;

        // Check if scan is complete (handle both uppercase and lowercase status)
        const statusLower = statusData.status?.toLowerCase();
        if (statusLower === 'completed') {
          stopPolling();
          onComplete?.(statusData.scanId || scanId);
        } else if (statusLower === 'failed') {
          stopPolling();
          onError?.(statusData.message || statusData.errorMessage || 'Scan failed');
        }
      } catch (error) {
        retryCountRef.current += 1;
        
        if (retryCountRef.current >= APP_CONSTANTS.MAX_RETRIES) {
          stopPolling();
          onError?.('Failed to get scan status after multiple retries');
        }
      }
    };

    // Start polling
    setIsPolling(true);
    pollStatus(); // Initial poll
    intervalRef.current = setInterval(pollStatus, APP_CONSTANTS.POLL_INTERVAL);

    // Set absolute timeout as safety net
    timeoutRef.current = setTimeout(() => {
      stopPolling();
      onError?.('Scan timed out after 5 minutes');
    }, MAX_POLLING_DURATION_MS);

    // Cleanup
    return () => {
      stopPolling();
    };
  }, [scanId, enabled, onComplete, onError]);

  return {
    status,
    isPolling,
  };
};
