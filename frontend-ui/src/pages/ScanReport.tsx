import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { Button } from '../components/common/Button';
import { Loader } from '../components/common/Loader';
import { RiskScoreCard } from '../components/dashboard/RiskScoreCard';
import { VulnerabilityList } from '../components/dashboard/VulnerabilityList';
import { MonacoEditorWrapper } from '../components/editor/MonacoEditorWrapper';
import { useRequireAuth } from '../hooks/useAuth';
import scanService, { ScanResult } from '../services/scanService';
import fileService from '../services/fileService';
import { Vulnerability, groupBySeverity } from '../utils/riskCalculator';
import { formatDate } from '../utils/dateFormat';
import { getFileExtension } from '../utils/fileUtils';

export const ScanReport: React.FC = () => {
  useRequireAuth();
  
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [highlightedLine, setHighlightedLine] = useState<number | undefined>();
  const [activeTab, setActiveTab] = useState<'all' | 'static' | 'ml'>('all');

  useEffect(() => {
    const fetchScanResult = async () => {
      if (!scanId) return;

      try {
        const result = await scanService.getScanResults(scanId);
        setScanResult(result);
      } catch (err: any) {
        setError(err.message || 'Failed to load scan results');
      } finally {
        setIsLoading(false);
      }
    };

    fetchScanResult();
  }, [scanId]);

  const handleVulnerabilityClick = (vuln: Vulnerability) => {
    const line = vuln.line || vuln.lineNumber;
    if (line) {
      setHighlightedLine(line);
    }
  };

  const handleDownloadPDF = async () => {
    if (!scanId || !scanResult) return;
    
    try {
      await fileService.downloadPDF(
        scanId,
        `${scanResult.contractName}_security_report.pdf`
      );
    } catch (err) {
      console.error('Failed to download PDF:', err);
    }
  };

  const getActiveVulnerabilities = (): Vulnerability[] => {
    if (!scanResult) return [];
    
    switch (activeTab) {
      case 'static':
        return scanResult.staticFindings || [];
      case 'ml':
        return scanResult.mlFindings || [];
      default:
        return scanResult.allVulnerabilities || scanResult.vulnerabilities || [];
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <Loader size="lg" text="Loading scan results..." />
      </div>
    );
  }

  if (error || !scanResult) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="bg-white rounded-lg shadow-md p-8 max-w-md">
            <svg
              className="w-16 h-16 text-red-500 mx-auto mb-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <h2 className="text-xl font-bold text-gray-900 mb-2">Error Loading Results</h2>
            <p className="text-gray-600 mb-6">{error}</p>
            <Button onClick={() => navigate('/dashboard')}>Back to Dashboard</Button>
          </div>
        </div>
      </div>
    );
  }

  const allVulns = scanResult.allVulnerabilities || scanResult.vulnerabilities || [];
  const groupedVulns = groupBySeverity(allVulns);
  const criticalCount = scanResult.criticalCount ?? groupedVulns['CRITICAL']?.length ?? groupedVulns['critical']?.length ?? 0;
  const highCount = scanResult.highCount ?? groupedVulns['HIGH']?.length ?? groupedVulns['high']?.length ?? 0;
  const mediumCount = scanResult.mediumCount ?? groupedVulns['MEDIUM']?.length ?? groupedVulns['medium']?.length ?? 0;
  const lowCount = scanResult.lowCount ?? groupedVulns['LOW']?.length ?? groupedVulns['low']?.length ?? 0;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div>
              <Link to="/dashboard" className="text-sm text-gray-500 hover:text-gray-700 mb-2 inline-block">
                ← Back to Dashboard
              </Link>
              <h1 className="text-2xl font-bold text-gray-900">
                {scanResult.contractName}
              </h1>
              <p className="text-sm text-gray-500 mt-1">
                Scanned on {formatDate(scanResult.uploadedAt || scanResult.startedAt || '')}
              </p>
            </div>
            <div className="space-x-3">
              <Button variant="outline" onClick={handleDownloadPDF}>
                Download PDF
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Risk Score & Vulnerabilities */}
          <div className="lg:col-span-1 space-y-6">
            <RiskScoreCard
              score={scanResult.riskScore}
              totalVulnerabilities={scanResult.allVulnerabilities.length}
              criticalCount={criticalCount}
              highCount={highCount}
              mediumCount={mediumCount}
              lowCount={lowCount}
            />

            {/* Tabs */}
            <div className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
              <div className="flex border-b border-gray-200">
                <button
                  className={`flex-1 px-4 py-3 text-sm font-medium ${
                    activeTab === 'all'
                      ? 'bg-primary text-white'
                      : 'bg-white text-gray-700 hover:bg-gray-50'
                  }`}
                  onClick={() => setActiveTab('all')}
                >
                  All ({scanResult.allVulnerabilities.length})
                </button>
                <button
                  className={`flex-1 px-4 py-3 text-sm font-medium border-l border-r border-gray-200 ${
                    activeTab === 'static'
                      ? 'bg-primary text-white'
                      : 'bg-white text-gray-700 hover:bg-gray-50'
                  }`}
                  onClick={() => setActiveTab('static')}
                >
                  Static ({scanResult.staticFindings.length})
                </button>
                <button
                  className={`flex-1 px-4 py-3 text-sm font-medium ${
                    activeTab === 'ml'
                      ? 'bg-primary text-white'
                      : 'bg-white text-gray-700 hover:bg-gray-50'
                  }`}
                  onClick={() => setActiveTab('ml')}
                >
                  ML ({scanResult.mlFindings.length})
                </button>
              </div>

              <div className="max-h-[600px] overflow-y-auto">
                <VulnerabilityList
                  vulnerabilities={getActiveVulnerabilities()}
                  onVulnerabilityClick={handleVulnerabilityClick}
                />
              </div>
            </div>
          </div>

          {/* Right Column - Code Editor */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-md p-4">
              <div className="mb-4">
                <h2 className="text-lg font-bold text-gray-900">Source Code</h2>
                <p className="text-sm text-gray-500">
                  Click on a vulnerability to highlight the affected line
                </p>
              </div>
              <MonacoEditorWrapper
                code={scanResult.sourceCode || '// Source code not available'}
                language={getFileExtension(scanResult.contractName)}
                highlightedLine={highlightedLine}
                height="700px"
              />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};
