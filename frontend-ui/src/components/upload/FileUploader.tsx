import React, { useRef, useState } from 'react';
import { isValidFileType, isValidFileSize, formatFileSize } from '../../utils/fileUtils';
import { MESSAGES } from '../../config/constants';
import { Button } from '../common/Button';

interface FileUploaderProps {
  onFileSelect: (file: File) => void;
  isUploading?: boolean;
}

export const FileUploader: React.FC<FileUploaderProps> = ({
  onFileSelect,
  isUploading = false,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const validateAndSetFile = (file: File) => {
    setError(null);

    if (!isValidFileType(file.name)) {
      setError(MESSAGES.ERROR.FILE_TYPE);
      return;
    }

    if (!isValidFileSize(file.size)) {
      setError(MESSAGES.ERROR.FILE_SIZE);
      return;
    }

    setSelectedFile(file);
    onFileSelect(file);
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleButtonClick = () => {
    inputRef.current?.click();
  };

  return (
    <div className="w-full">
      <div
        className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-all ${
          dragActive
            ? 'border-primary bg-blue-50'
            : 'border-gray-300 hover:border-gray-400'
        } ${isUploading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={!isUploading ? handleButtonClick : undefined}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept=".sol,.move"
          onChange={handleChange}
          disabled={isUploading}
        />

        <div className="flex flex-col items-center">
          <svg
            className="w-16 h-16 text-gray-400 mb-4"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
            />
          </svg>

          {selectedFile ? (
            <div className="space-y-2">
              <p className="text-sm font-medium text-gray-900">{selectedFile.name}</p>
              <p className="text-xs text-gray-500">{formatFileSize(selectedFile.size)}</p>
              {!isUploading && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedFile(null);
                    setError(null);
                    if (inputRef.current) inputRef.current.value = '';
                  }}
                >
                  Change File
                </Button>
              )}
            </div>
          ) : (
            <>
              <p className="text-base font-medium text-gray-700 mb-2">
                Drop your smart contract here or click to browse
              </p>
              <p className="text-sm text-gray-500">
                Supports .sol (Solidity) and .move (Move) files
              </p>
              <p className="text-xs text-gray-400 mt-1">Max file size: 10MB</p>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-sm text-red-600">{error}</p>
        </div>
      )}
    </div>
  );
};
