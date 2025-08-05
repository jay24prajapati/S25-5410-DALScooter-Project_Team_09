import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast } from 'react-toastify';
import { Eye, EyeOff } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function ResetPassword() {
  const location = useLocation();
  const navigate = useNavigate();
  const { sessionId, email } = location.state || {};

  const [verificationCode, setVerificationCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match!');
      return;
    }

    try {
      await axios.post(`${API_BASE}/auth/reset-password`, {
        email,
        sessionId,
        verificationCode,
        newPassword
      });

      toast.success('Password reset successfully!');
      navigate('/login');
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Reset failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-blue-50 px-4">
      <div className="bg-white p-10 rounded-2xl shadow-xl w-full max-w-md border border-blue-200">
        <h2 className="text-2xl font-bold text-blue-800 text-center mb-6">Reset Password</h2>
        <form onSubmit={handleSubmit} className="space-y-5">
          <input
            type="text"
            placeholder="Verification Code"
            value={verificationCode}
            onChange={(e) => setVerificationCode(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-xl bg-blue-50/30 focus:outline-none focus:border-blue-500"
          />
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="New Password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-xl bg-blue-50/30 focus:outline-none focus:border-blue-500"
            />
            <span
              className="absolute right-4 top-3 cursor-pointer text-gray-500"
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
            </span>
          </div>
          <input
            type={showPassword ? 'text' : 'password'}
            placeholder="Confirm Password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-xl bg-blue-50/30 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            className="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 rounded-xl shadow-md"
          >
            Reset Password
          </button>
        </form>
      </div>
    </div>
  );
}
