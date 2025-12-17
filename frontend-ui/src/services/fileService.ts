import apiClient, { handleApiError } from './apiClient';
import { API_ENDPOINTS } from '../config/api.config';

class FileService {
  /**
   * Download PDF report
   */
  async downloadPDF(scanId: string, filename: string = 'report.pdf'): Promise<void> {
    try {
      const url = API_ENDPOINTS.DOWNLOAD_PDF.replace(':id', scanId);
      const response = await apiClient.get(url, {
        responseType: 'blob',
      });

      // Create blob link to download
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = filename;
      link.click();
      
      // Clean up
      window.URL.revokeObjectURL(link.href);
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }

  /**
   * Share report (generate shareable link)
   */
  async shareReport(scanId: string): Promise<{ shareUrl: string }> {
    try {
      const url = API_ENDPOINTS.SHARE_REPORT.replace(':id', scanId);
      const response = await apiClient.post<{ success: boolean; data: { shareUrl: string } }>(url);
      return response.data.data;
    } catch (error) {
      throw new Error(handleApiError(error));
    }
  }

  /**
   * Read file content as text
   */
  async readFileAsText(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        if (e.target?.result) {
          resolve(e.target.result as string);
        } else {
          reject(new Error('Failed to read file'));
        }
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  }
}

export default new FileService();
