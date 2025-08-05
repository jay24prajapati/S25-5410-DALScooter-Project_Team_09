import React, { useState } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function ForgotPassword() {
  const [email, setEmail] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/auth/forgot-password`, { email });
      const { sessionId } = res.data;

      toast.success('Reset instructions sent to your email!');

      // Redirect to ResetPassword and pass sessionId and email
      navigate('/reset-password', {
        state: {
          sessionId,
          email
        }
      });
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Error sending reset email');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-blue-50 px-4">
      <div className="bg-white p-10 rounded-2xl shadow-xl w-full max-w-md border border-blue-200">
        <h2 className="text-2xl font-bold text-blue-800 text-center mb-6">Forgot Password</h2>
        <form onSubmit={handleSubmit} className="space-y-5">
          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-xl bg-blue-50/30 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-xl shadow-md"
          >
            Send Reset Instructions
          </button>
        </form>
      </div>
    </div>
  );
}
