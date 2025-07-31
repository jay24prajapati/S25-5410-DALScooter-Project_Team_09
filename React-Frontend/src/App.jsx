import { Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import CustomerDashboard from './pages/CustomerDashboard';
import AuthPage from './pages/AuthPage';
import RegisterPage from './pages/RegisterPage';

import LoginPage from './pages/LoginPage';
import FranchiseDashboard from './pages/FranchiseDashboard.JSX'; // 🔐 NEW

import ProtectedFranchiseRoute from './routes/ProtectedFranchiseRoute'; // 🔐 NEW

import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

function App() {
  return (
    <div className="App">
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/customer-dashboard" element={<CustomerDashboard />} />
        <Route path="/auth" element={<AuthPage />} />
        <Route path="/register" element={<RegisterPage />} />
       
        <Route path="/login" element={<LoginPage />} />
        
        {/* 🔐 Protected Route */}
        <Route
          path="/franchise-dashboard"
          element={
            <ProtectedFranchiseRoute>
              <FranchiseDashboard />
            </ProtectedFranchiseRoute>
          }
        />
      </Routes>
      <ToastContainer position="top-center" autoClose={3000} />
    </div>
  );
}

export default App;
