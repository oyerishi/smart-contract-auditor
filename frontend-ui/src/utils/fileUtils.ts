import { SUPPORTED_FILE_TYPES } from '../config/api.config';
import { API_CONFIG } from '../config/api.config';

/**
 * Validate file type
 */
export const isValidFileType = (filename: string): boolean => {
  const extension = filename.substring(filename.lastIndexOf('.')).toLowerCase();
  const allExtensions = [...SUPPORTED_FILE_TYPES.SOLIDITY, ...SUPPORTED_FILE_TYPES.MOVE];
  return allExtensions.includes(extension);
};

/**
 * Validate file size
 */
export const isValidFileSize = (size: number): boolean => {
  return size <= API_CONFIG.MAX_FILE_SIZE;
};

/**
 * Format file size to readable string
 */
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};

/**
 * Get file extension
 */
export const getFileExtension = (filename: string): string => {
  return filename.substring(filename.lastIndexOf('.')).toLowerCase();
};

/**
 * Generate unique file ID
 */
export const generateFileId = (): string => {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};
