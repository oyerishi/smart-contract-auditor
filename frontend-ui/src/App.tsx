import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ScanProvider } from './context/ScanContext';
import { Home } from './pages/Home';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { Dashboard } from './pages/Dashboard';
import { ScanReport } from './pages/ScanReport';

function App() {
  return (
    <Router>
      <AuthProvider>
        <ScanProvider>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scan/:scanId" element={<ScanReport />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </ScanProvider>
      </AuthProvider>
    </Router>
  );
}

export default App;
