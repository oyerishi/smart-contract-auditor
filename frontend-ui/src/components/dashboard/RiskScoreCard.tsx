import React from 'react';
import { getRiskLevel, getSeverityColor } from '../../utils/riskCalculator';

interface RiskScoreCardProps {
  score: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export const RiskScoreCard: React.FC<RiskScoreCardProps> = ({
  score,
  totalVulnerabilities,
  criticalCount,
  highCount,
  mediumCount,
  lowCount,
}) => {
  const riskLevel = getRiskLevel(score);
  
  const getRiskColor = (level: string) => {
    if (level === 'Critical') return 'text-red-600 bg-red-50 border-red-200';
    if (level === 'High') return 'text-orange-600 bg-orange-50 border-orange-200';
    if (level === 'Medium') return 'text-yellow-600 bg-yellow-50 border-yellow-200';
    if (level === 'Low') return 'text-blue-600 bg-blue-50 border-blue-200';
    return 'text-green-600 bg-green-50 border-green-200';
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200">
      <h2 className="text-xl font-bold text-gray-900 mb-4">Risk Assessment</h2>
      
      <div className={`border-2 rounded-lg p-6 mb-6 ${getRiskColor(riskLevel)}`}>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium uppercase tracking-wide">Overall Risk</p>
            <p className="text-4xl font-bold mt-1">{riskLevel}</p>
          </div>
          <div className="text-right">
            <div className="text-5xl font-bold">{Number(score).toFixed(2)}</div>
            <p className="text-sm mt-1">/ 100</p>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-gray-700">Total Issues</span>
          <span className="text-lg font-bold text-gray-900">{totalVulnerabilities}</span>
        </div>

        <div className="border-t border-gray-200 pt-3 space-y-2">
          {criticalCount > 0 && (
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-600 rounded-full"></div>
                <span className="text-sm text-gray-700">Critical</span>
              </div>
              <span className="font-semibold text-red-600">{criticalCount}</span>
            </div>
          )}
          
          {highCount > 0 && (
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-orange-600 rounded-full"></div>
                <span className="text-sm text-gray-700">High</span>
              </div>
              <span className="font-semibold text-orange-600">{highCount}</span>
            </div>
          )}
          
          {mediumCount > 0 && (
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-yellow-600 rounded-full"></div>
                <span className="text-sm text-gray-700">Medium</span>
              </div>
              <span className="font-semibold text-yellow-600">{mediumCount}</span>
            </div>
          )}
          
          {lowCount > 0 && (
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-blue-600 rounded-full"></div>
                <span className="text-sm text-gray-700">Low</span>
              </div>
              <span className="font-semibold text-blue-600">{lowCount}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
