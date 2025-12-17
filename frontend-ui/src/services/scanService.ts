import apiClient, { handleApiError } from './apiClient';
import { API_ENDPOINTS } from '../config/api.config';
import { Vulnerability } from '../utils/riskCalculator';

export interface ScanStatus {
  id: string;
  scanId?: string;
  status: 'pending' | 'uploading' | 'analyzing' | 'completed' | 'failed' | 'PENDING' | 'COMPLETED' | 'FAILED';
  progress?: number;
  message?: string;
  errorMessage?: string;
}

export interface ScanResult {
  id: string;
  scanId?: string;
  contractName: string;
  uploadedAt: string;
  startedAt?: string;
  completedAt?: string;
  status: string;
  riskScore: number;
  totalVulnerabilities?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  staticFindings: Vulnerability[];
  mlFindings: Vulnerability[];
  allVulnerabilities: Vulnerability[];
  vulnerabilities?: Vulnerability[];
  sourceCode?: string;
  errorMessage?: string;
}

export interface ScanHistoryItem {
  id: string;
  scanId: string;
  contractName: string;
  startedAt: string;
  uploadedAt?: string;
  completedAt?: string;
  status: string;
  riskScore: number;
  totalVulnerabilities: number;
  vulnerabilityCount?: number;
  errorMessage?: string;
}

class ScanService {
  /**
   * Upload smart contract for analysis
   */
  async uploadContract(file: File): Promise<{ scanId: string }> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('contractName', file.name);

      const response = await apiClient.post<{ success: boolean; data: { scanId: string } }>(
        API_ENDPOINTS.UPLOAD_CONTRACT,
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      return response.data.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }

  /**
   * Check scan status
   */
  async getScanStatus(scanId: string): Promise<ScanStatus> {
    try {
      const url = API_ENDPOINTS.SCAN_STATUS.replace(':id', scanId);
      const response = await apiClient.get<{ success: boolean; data: ScanStatus }>(url);
      return response.data.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }

  /**
   * Get scan results
   */
  async getScanResults(scanId: string): Promise<ScanResult> {
    try {
      const url = API_ENDPOINTS.SCAN_RESULTS.replace(':id', scanId);
      const response = await apiClient.get<{ success: boolean; data: ScanResult }>(url);
      return response.data.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }

  /**
   * Get scan history for current user
   */
  async getScanHistory(): Promise<ScanHistoryItem[]> {
    try {
      const response = await apiClient.get<{ success: boolean; data: ScanHistoryItem[] }>(
        API_ENDPOINTS.SCAN_HISTORY
      );
      return response.data.data || [];
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }

  /**
   * Delete a scan
   */
  async deleteScan(scanId: string): Promise<void> {
    try {
      await apiClient.delete(`/contracts/scan/${scanId}`);
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }
}

export default new ScanService();
