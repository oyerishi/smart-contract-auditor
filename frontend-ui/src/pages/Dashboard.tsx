import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button } from '../components/common/Button';
import { Loader } from '../components/common/Loader';
import { FileUploader } from '../components/upload/FileUploader';
import { useAuth } from '../context/AuthContext';
import { useScan } from '../context/ScanContext';
import { useRequireAuth } from '../hooks/useAuth';
import { useScanPolling } from '../hooks/useScanPolling';
import scanService, { ScanHistoryItem } from '../services/scanService';
import { MESSAGES } from '../config/constants';
import { formatRelativeTime } from '../utils/dateFormat';
import { getRiskLevel } from '../utils/riskCalculator';

export const Dashboard: React.FC = () => {
  useRequireAuth();
  
  const { user, logout } = useAuth();
  const { scanState, setCurrentScan, updateScanStatus, setError, resetScan } = useScan();
  const navigate = useNavigate();
  
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(true);

  // Clear stale scan state on mount
  useEffect(() => {
    // Reset scan state if there's a stale scan ID from a previous session
    if (scanState.currentScanId && scanState.scanStatus === 'analyzing') {
      // Check if this scan ID is already in the history (meaning it completed)
      const fetchAndCheck = async () => {
        try {
          const history = await scanService.getScanHistory();
          const existingScan = history.find(s => 
            (s.scanId === scanState.currentScanId || s.id === scanState.currentScanId)
          );
          if (existingScan) {
            // Scan already completed, reset state
            resetScan();
          }
          setScanHistory(history);
          setIsLoadingHistory(false);
        } catch (err) {
          console.error('Failed to fetch history:', err);
          setIsLoadingHistory(false);
        }
      };
      fetchAndCheck();
    } else {
      // Normal history fetch
      const fetchHistory = async () => {
        try {
          const history = await scanService.getScanHistory();
          setScanHistory(history);
        } catch (err) {
          console.error('Failed to fetch history:', err);
        } finally {
          setIsLoadingHistory(false);
        }
      };
      fetchHistory();
    }
  }, []);

  // Poll for scan status
  useScanPolling({
    scanId: scanState.currentScanId,
    enabled: !!scanState.currentScanId && scanState.scanStatus === 'analyzing',
    onComplete: (scanId) => {
      updateScanStatus('completed');
      resetScan();
      navigate(`/scan/${scanId}`);
    },
    onError: (error) => {
      setError(error);
      resetScan();
    },
  });

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!selectedFile) return;

    setIsUploading(true);
    try {
      const { scanId } = await scanService.uploadContract(selectedFile);
      setCurrentScan(scanId);
      updateScanStatus('analyzing', 30);
    } catch (err: any) {
      setError(err.message || MESSAGES.ERROR.UPLOAD_FAILED);
      setIsUploading(false);
    }
  };

  const getRiskColor = (score: number) => {
    const level = getRiskLevel(score);
    if (level === 'Critical') return 'text-red-600';
    if (level === 'High') return 'text-orange-600';
    if (level === 'Medium') return 'text-yellow-600';
    if (level === 'Low') return 'text-blue-600';
    return 'text-green-600';
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <Link to="/">
              <h1 className="text-2xl font-bold text-gray-900">
                Smart Contract Security Auditor
              </h1>
            </Link>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">Welcome, {user?.username || user?.email}</span>
              <Button variant="outline" size="sm" onClick={logout}>
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Upload Section */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">New Security Audit</h2>
          
          <FileUploader
            onFileSelect={handleFileSelect}
            isUploading={isUploading || scanState.scanStatus === 'analyzing'}
          />

          {selectedFile && !scanState.currentScanId && (
            <div className="mt-4">
              <Button onClick={handleUpload} isLoading={isUploading} size="lg">
                Start Analysis
              </Button>
            </div>
          )}

          {/* Scanning Progress */}
          {scanState.currentScanId && scanState.scanStatus !== 'completed' && (
            <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="flex items-center space-x-3">
                <Loader size="sm" />
                <div className="flex-1">
                  <p className="font-medium text-gray-900">
                    {scanState.scanStatus === 'uploading' && 'Uploading contract...'}
                    {scanState.scanStatus === 'analyzing' && 'Analyzing contract...'}
                  </p>
                  <p className="text-sm text-gray-600 mt-1">
                    Running static analysis and ML detection. This may take 1-2 minutes.
                  </p>
                </div>
              </div>
            </div>
          )}

          {scanState.error && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
              <p className="text-sm text-red-600">{scanState.error}</p>
            </div>
          )}
        </div>

        {/* Scan History */}
        <div className="bg-white rounded-lg shadow-md">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-xl font-bold text-gray-900">Recent Audits</h2>
          </div>

          {isLoadingHistory ? (
            <Loader />
          ) : scanHistory.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-gray-500">No audits yet. Upload your first contract above!</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200">
              {scanHistory.map((scan) => (
                <Link
                  key={scan.scanId || scan.id}
                  to={`/scan/${scan.scanId || scan.id}`}
                  className="block p-6 hover:bg-gray-50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900">
                        {scan.contractName}
                      </h3>
                      <p className="text-sm text-gray-500 mt-1">
                        {formatRelativeTime(scan.startedAt)}
                      </p>
                    </div>
                    
                    <div className="flex items-center space-x-6">
                      <div className="text-right">
                        <p className="text-sm text-gray-500">Risk Score</p>
                        <p className={`text-2xl font-bold ${getRiskColor(scan.riskScore)}`}>
                          {Number(scan.riskScore).toFixed(2)}
                        </p>
                      </div>
                      
                      <div className="text-right">
                        <p className="text-sm text-gray-500">Issues Found</p>
                        <p className="text-2xl font-bold text-gray-900">
                          {scan.totalVulnerabilities ?? scan.vulnerabilityCount ?? 0}
                        </p>
                      </div>
                      
                      <svg
                        className="w-6 h-6 text-gray-400"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 5l7 7-7 7"
                        />
                      </svg>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};
