import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '../components/common/Button';
import { useAuth } from '../context/AuthContext';

export const Home: React.FC = () => {
  const { isAuthenticated } = useAuth();

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-purple-50">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold text-gray-900">
              Smart Contract Security Auditor
            </h1>
            <div className="space-x-4">
              {isAuthenticated ? (
                <Link to="/dashboard">
                  <Button>Dashboard</Button>
                </Link>
              ) : (
                <>
                  <Link to="/login">
                    <Button variant="outline">Login</Button>
                  </Link>
                  <Link to="/register">
                    <Button>Get Started</Button>
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="text-center">
            <h2 className="text-5xl font-extrabold text-gray-900 mb-6">
              Secure Your Smart Contracts
              <span className="block text-primary mt-2">With AI-Powered Analysis</span>
            </h2>
            <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
              Comprehensive security auditing for Solidity and Move smart contracts.
              Combines static analysis with machine learning to detect vulnerabilities
              before deployment.
            </p>
            <div className="flex justify-center space-x-4">
              <Link to={isAuthenticated ? '/dashboard' : '/register'}>
                <Button size="lg">Start Free Audit</Button>
              </Link>
              <a href="#features">
                <Button variant="outline" size="lg">
                  Learn More
                </Button>
              </a>
            </div>
          </div>

          {/* Features Section */}
          <div id="features" className="mt-24 grid md:grid-cols-3 gap-8">
            <div className="bg-white rounded-lg shadow-md p-6">
              <div className="w-12 h-12 bg-primary rounded-lg flex items-center justify-center mb-4">
                <svg
                  className="w-6 h-6 text-white"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-gray-900 mb-2">
                Static Analysis
              </h3>
              <p className="text-gray-600">
                Deterministic rule-based checking for known vulnerability patterns
                using industry-standard security frameworks.
              </p>
            </div>

            <div className="bg-white rounded-lg shadow-md p-6">
              <div className="w-12 h-12 bg-secondary rounded-lg flex items-center justify-center mb-4">
                <svg
                  className="w-6 h-6 text-white"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                  />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-gray-900 mb-2">
                ML Detection
              </h3>
              <p className="text-gray-600">
                Advanced machine learning models trained on thousands of contracts
                to detect semantic vulnerabilities and logic flaws.
              </p>
            </div>

            <div className="bg-white rounded-lg shadow-md p-6">
              <div className="w-12 h-12 bg-success rounded-lg flex items-center justify-center mb-4">
                <svg
                  className="w-6 h-6 text-white"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                  />
                </svg>
              </div>
              <h3 className="text-xl font-bold text-gray-900 mb-2">
                Detailed Reports
              </h3>
              <p className="text-gray-600">
                Comprehensive vulnerability reports with line-level highlighting,
                severity ratings, and remediation recommendations.
              </p>
            </div>
          </div>

          {/* Stats Section */}
          <div className="mt-24 bg-white rounded-lg shadow-md p-8">
            <div className="grid md:grid-cols-4 gap-8 text-center">
              <div>
                <p className="text-4xl font-bold text-primary">10,000+</p>
                <p className="text-gray-600 mt-2">Contracts Analyzed</p>
              </div>
              <div>
                <p className="text-4xl font-bold text-secondary">99.9%</p>
                <p className="text-gray-600 mt-2">Accuracy Rate</p>
              </div>
              <div>
                <p className="text-4xl font-bold text-success">50+</p>
                <p className="text-gray-600 mt-2">Vulnerability Types</p>
              </div>
              <div>
                <p className="text-4xl font-bold text-danger">&lt; 2min</p>
                <p className="text-gray-600 mt-2">Average Scan Time</p>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-24">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <p className="text-center text-gray-500 text-sm">
            © 2025 Smart Contract Security Auditor. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
};
