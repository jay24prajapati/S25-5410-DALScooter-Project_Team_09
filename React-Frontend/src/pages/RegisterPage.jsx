import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, EyeOff } from 'lucide-react';
import { toast } from 'react-toastify';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function RegisterPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    userType: '',
    securityQuestion: '',
    securityAnswer: '',
  });

  const [verificationCode, setVerificationCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
  e.preventDefault();
  setLoading(true);

  if (form.password !== form.confirmPassword) {
    toast.error('Passwords do not match.');
    setLoading(false);
    return;
  }

  try {
    const { confirmPassword, ...payload } = form;
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    if (!res.ok) {
      const message = data?.message || data?.error || 'Registration failed';
      throw new Error(message);
    }

    toast.success('Registered successfully! Please check your email.');
    setStep(2);
  } catch (err) {
    toast.error(`Registration failed: ${err.message}`);
  } finally {
    setLoading(false);
  }
};


  const handleVerify = async (e) => {
  e.preventDefault();
  setLoading(true);
  try {
    const res = await fetch(`${API_BASE}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: form.email, verificationCode }),
    });
    const data = await res.json();

    if (!res.ok) {
      const message = data?.message || data?.error || 'Verification failed';
      throw new Error(message);
    }

    toast.success('✅ Email verified! Redirecting...');
    setTimeout(() => navigate('/login'), 1500);
  } catch (err) {
    toast.error(`Verification failed: ${err.message}`);
  } finally {
    setLoading(false);
  }
};


  const handleResendCode = async () => {
  setLoading(true);
  try {
    const res = await fetch(`${API_BASE}/auth/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: form.email }),
    });
    const data = await res.json();

    if (!res.ok) {
      const message = data?.message || data?.error || 'Failed to resend code';
      throw new Error(message);
    }

    toast.success('🔄 Verification code resent to your email.');
  } catch (err) {
    toast.error(`Resend failed: ${err.message}`);
  } finally {
    setLoading(false);
  }
};


  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-xl p-6 w-full max-w-sm border border-blue-200">
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-blue-800 mb-2">
            {step === 1 ? 'User Registration' : 'Verify Email'}
          </h2>
          <div className="w-16 h-1 bg-gradient-to-r from-blue-400 to-blue-600 mx-auto rounded-full"></div>
        </div>

        {step === 1 ? (
          <form onSubmit={handleRegister} className="space-y-6">
            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Email</label>
              <input
                type="email"
                name="email"
                value={form.email}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg bg-blue-50/30"
                placeholder="Enter your email"
              />
            </div>

            {/* Password */}
            <div className="space-y-2 relative">
              <label className="block text-sm font-semibold text-blue-700">Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                value={form.password}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 pr-12 border-2 border-blue-200 rounded-lg bg-blue-50/30"
                placeholder="Enter your password"
              />
              <div
                className="absolute right-3 top-[38px] cursor-pointer text-blue-500"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </div>
            </div>

            {/* Confirm Password */}
            <div className="space-y-2 relative">
              <label className="block text-sm font-semibold text-blue-700">Confirm Password</label>
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                name="confirmPassword"
                value={form.confirmPassword}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 pr-12 border-2 border-blue-200 rounded-lg bg-blue-50/30"
                placeholder="Rewrite your password"
              />
              <div
                className="absolute right-3 top-[38px] cursor-pointer text-blue-500"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </div>
            </div>

            {/* User Type */}
            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">User Type</label>
              <select
                name="userType"
                value={form.userType}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg bg-blue-50/30"
              >
                <option value="">Select user type...</option>
                <option value="customer">Customer</option>
                <option value="franchise">Franchise Operator</option>
              </select>
            </div>

            {/* Security Question */}
            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Security Question</label>
              <select
                name="securityQuestion"
                value={form.securityQuestion}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg bg-blue-50/30"
              >
                <option value="">Choose a question...</option>
                <option>What is your favorite color?</option>
                <option>What city were you born in?</option>
                <option>What is your pet's name?</option>
                <option>What is your favorite food?</option>
                <option>What was your first car?</option>
              </select>
            </div>

            {/* Security Answer */}
            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Security Answer</label>
              <input
                type="text"
                name="securityAnswer"
                value={form.securityAnswer}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg bg-blue-50/30"
                placeholder="Enter your answer"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white font-bold py-3 rounded-lg hover:scale-105 transition-all"
            >
              {loading ? 'Registering...' : 'Register'}
            </button>
            {/* Divider */}
<div className="relative my-6">
  <div className="absolute inset-0 flex items-center">
    <div className="w-full border-t border-blue-200"></div>
  </div>
  <div className="relative flex justify-center text-sm">
    <span className="bg-white px-2 text-blue-500">Already have an account?</span>
  </div>
</div>

{/* Go to Login Button */}
<button
  type="button"
  onClick={() => navigate('/login')}
  className="w-full border border-blue-500 text-blue-600 font-medium py-2 rounded-lg hover:bg-blue-50 transition-all"
>
  Sign in to your account
</button>

          </form>
        ) : (
          <form onSubmit={handleVerify} className="space-y-6">
            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Enter Verification Code</label>
              <input
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg bg-blue-50/30"
                placeholder="Code from your email"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-green-500 text-white font-bold py-3 rounded-lg hover:scale-105 transition-all"
            >
              {loading ? 'Verifying...' : 'Verify Email'}
            </button>

            <button
              type="button"
              onClick={handleResendCode}
              disabled={loading}
              className="w-full bg-yellow-100 text-yellow-800 font-medium py-2 rounded-lg hover:bg-yellow-200"
            >
              {loading ? 'Resending...' : 'Resend Verification Code'}
            </button>

            <button
              type="button"
              onClick={() => setStep(1)}
              className="w-full text-sm text-blue-600 underline text-center"
            >
              ← Back to registration
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
