import { Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import CustomerDashboard from './pages/CustomerDashboard';
import AuthPage from './pages/AuthPage';
import RegisterPage from './pages/RegisterPage';
import LoginPage from './pages/LoginPage';
import ProtectedFranchiseRoute from './routes/ProtectedFranchiseRoute'; 
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import FranchiseDashboard from './pages/FranchiseDashboard.JSX';
import ForgotPassword from './pages/ForgotPassword.jsx';
import ResetPassword from './pages/ResetPassword.jsx';
import StatsPage from './pages/Analytics/Analytics.js';
function App() {  
  return (
    <div className="App">
      <Routes>
        <Route path="/customer-dashboard" element={<CustomerDashboard />} />
        <Route path="/" element={<LandingPage />} />
        <Route path="/auth" element={<AuthPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/stats" element={<StatsPage />} />

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
