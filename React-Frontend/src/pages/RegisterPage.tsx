import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const API_BASE = 'https://288cs0y4la.execute-api.us-east-1.amazonaws.com/dev/auth';

export default function RegisterPage() {
  const navigate = useNavigate();

  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    email: '',
    password: '',
    userType: '',
    securityQuestion: '',
    securityAnswer: '',
  });

  const [verificationCode, setVerificationCode] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await fetch(`${API_BASE}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Registration failed');
      setSuccess('Registered successfully! Please check your email.');
      setStep(2);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await fetch(`${API_BASE}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: form.email, verificationCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Verification failed');
      setSuccess('✅ Email verified! Redirecting to login...');
      setTimeout(() => navigate('/login'), 1500);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-xl p-8 w-full max-w-md border border-blue-200">
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-blue-800 mb-2">
            {step === 1 ? 'User Registration' : 'Verify Email'}
          </h2>
          <div className="w-16 h-1 bg-gradient-to-r from-blue-400 to-blue-600 mx-auto rounded-full"></div>
        </div>

        {error && <div className="text-red-600 text-sm mb-4 text-center">{error}</div>}
        {success && <div className="text-green-600 text-sm mb-4 text-center">{success}</div>}

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
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none bg-blue-50/30 text-gray-800 placeholder-blue-300"
                placeholder="Enter your email"
              />
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Password</label>
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none bg-blue-50/30 text-gray-800 placeholder-blue-300"
                placeholder="Enter your password"
              />
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">User Type</label>
              <select
                name="userType"
                value={form.userType}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 bg-blue-50/30 text-gray-800"
              >
                <option value="">Select user type...</option>
                <option value="customer">Customer</option>
                <option value="franchise">Franchise Operator</option>
              </select>
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Security Question</label>
              <select
                name="securityQuestion"
                value={form.securityQuestion}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 bg-blue-50/30 text-gray-800"
              >
                <option value="">Choose a security question...</option>
                <option>What is your favorite color?</option>
                <option>What city were you born in?</option>
                <option>What is your pet's name?</option>
                <option>What is your favorite food?</option>
                <option>What was your first car?</option>
              </select>
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-semibold text-blue-700">Security Answer</label>
              <input
                type="text"
                name="securityAnswer"
                value={form.securityAnswer}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 bg-blue-50/30 text-gray-800 placeholder-blue-300"
                placeholder="Enter your answer"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
            >
              {loading ? 'Registering...' : 'Register'}
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
                className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 bg-blue-50/30 text-gray-800 placeholder-blue-300"
                placeholder="Code from your email"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
            >
              {loading ? 'Verifying...' : 'Verify Email'}
            </button>

            <button
              type="button"
              onClick={() => setStep(1)}
              className="w-full text-sm text-blue-600 underline mt-2 text-center"
            >
              ← Back to registration
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
