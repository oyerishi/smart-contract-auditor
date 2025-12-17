import React, { createContext, useContext, useState, ReactNode } from 'react';

interface ScanState {
  currentScanId: string | null;
  scanStatus: 'idle' | 'uploading' | 'analyzing' | 'completed' | 'failed';
  progress: number;
  error: string | null;
}

interface ScanContextType {
  scanState: ScanState;
  setCurrentScan: (scanId: string) => void;
  updateScanStatus: (status: ScanState['scanStatus'], progress?: number) => void;
  setError: (error: string) => void;
  resetScan: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

const initialState: ScanState = {
  currentScanId: null,
  scanStatus: 'idle',
  progress: 0,
  error: null,
};

export const ScanProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [scanState, setScanState] = useState<ScanState>(initialState);

  const setCurrentScan = (scanId: string) => {
    setScanState((prev) => ({
      ...prev,
      currentScanId: scanId,
      scanStatus: 'uploading',
      progress: 0,
      error: null,
    }));
  };

  const updateScanStatus = (status: ScanState['scanStatus'], progress: number = 0) => {
    setScanState((prev) => ({
      ...prev,
      scanStatus: status,
      progress,
    }));
  };

  const setError = (error: string) => {
    setScanState((prev) => ({
      ...prev,
      error,
      scanStatus: 'failed',
    }));
  };

  const resetScan = () => {
    setScanState(initialState);
  };

  return (
    <ScanContext.Provider
      value={{
        scanState,
        setCurrentScan,
        updateScanStatus,
        setError,
        resetScan,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export const useScan = () => {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};
