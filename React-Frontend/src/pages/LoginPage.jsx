import React, { useState } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

export default function LoginPage() {
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [decodedWord, setDecodedWord] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [userId, setUserId] = useState('');
  const [securityQuestion, setSecurityQuestion] = useState('');
  const [caesarChallenge, setCaesarChallenge] = useState('');
  const [accessToken, setAccessToken] = useState('');

  const API_BASE = import.meta.env.VITE_API_BASE;

  const handleStep1 = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, {
        step: 1,
        username: email,
        password,
      });
      const data = res.data;
      setSessionId(data.sessionId);
      setUserId(data.userId);
      setSecurityQuestion(data.securityQuestion);
      setStep(data.nextStep);
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        (err?.response?.status === 401 ? 'Invalid username or password' : 'Something went wrong in Step 1');
      toast.error(`Step 1 failed: ${message}`);
    }
  };

  const handleStep2 = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, {
        step: 2,
        sessionId,
        userId,
        securityAnswer,
      });
      const data = res.data;
      setSessionId(data.sessionId);
      setCaesarChallenge(data.caesarChallenge);
      setStep(data.nextStep);
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        (err?.response?.status === 401 ? 'Incorrect security answer' : 'Something went wrong in Step 2');
      toast.error(`Step 2 failed: ${message}`);
    }
  };

  const handleStep3 = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_BASE}/auth/login`, {
        step: 3,
        sessionId,
        userId,
        caesarAnswer: decodedWord,
      });
      const data = res.data;
      setAccessToken(data.accessToken);
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('sessionId', sessionId);
      localStorage.setItem('userType', data.userType);
      localStorage.setItem('email', email);

      toast.success('Login successful!');
      window.location.href =
        data.userType === 'franchise' ? '/franchise-dashboard' : '/customer-dashboard';
    } catch (err) {
      const message =
        err?.response?.data?.message ||
        (err?.response?.status === 401 ? 'Incorrect Caesar cipher solution' : 'Something went wrong in Step 3');
      toast.error(`Step 3 failed: ${message}`);
    }
  };


  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-blue-100 to-blue-200 flex items-center justify-center px-4 py-8">
      <div className="bg-white p-10 rounded-3xl shadow-2xl w-full max-w-lg border border-blue-200 relative overflow-hidden">
        
        {/* Background decoration */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-200 to-blue-300 opacity-20 rounded-full -mr-16 -mt-16"></div>
        <div className="absolute bottom-0 left-0 w-24 h-24 bg-gradient-to-tr from-blue-200 to-blue-300 opacity-20 rounded-full -ml-12 -mb-12"></div>
        
        {/* Header */}
        <div className="text-center mb-8 relative z-10">
          <div className="w-20 h-20 bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-lg">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-4xl font-bold text-blue-800 mb-3">3-Factor Login</h2>
          <div className="w-20 h-1 bg-gradient-to-r from-blue-400 to-blue-600 mx-auto rounded-full"></div>
          <p className="text-blue-600 text-sm mt-3">Secure authentication system</p>
        </div>

        {/* Progress Steps */}
        <div className="flex items-center justify-center space-x-4 mb-10 relative z-10">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold shadow-lg transition-all duration-300 ${
            step >= 1 ? 'bg-blue-500 text-white' : 'bg-blue-100 text-blue-400 border border-blue-200'
          }`}>
            {step > 1 ? '✓' : '1'}
          </div>
          <div className={`w-16 h-1 rounded-full ${step > 1 ? 'bg-blue-400' : 'bg-blue-200'}`}></div>
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold shadow-lg transition-all duration-300 ${
            step >= 2 ? 'bg-blue-500 text-white' : 'bg-blue-100 text-blue-400 border border-blue-200'
          }`}>
            {step > 2 ? '✓' : '2'}
          </div>
          <div className={`w-16 h-1 rounded-full ${step > 2 ? 'bg-blue-400' : 'bg-blue-200'}`}></div>
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold shadow-lg transition-all duration-300 ${
            step >= 3 ? 'bg-blue-500 text-white' : 'bg-blue-100 text-blue-400 border border-blue-200'
          }`}>
            3
          </div>
        </div>

        {/* Step 1 */}
        {step === 1 && (
          <form onSubmit={handleStep1} className="space-y-6 relative z-10">
            <div className="text-center mb-6">
              <p className="text-blue-600 font-semibold">Enter your credentials</p>
            </div>
            <div className="space-y-5">
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                  </svg>
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="Email"
                  className="w-full pl-12 pr-4 py-4 border-2 border-blue-200 rounded-xl focus:border-blue-500 focus:outline-none transition-all bg-blue-50/30 text-gray-800 placeholder-blue-400 shadow-sm"
                />
              </div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="Password"
                  className="w-full pl-12 pr-4 py-4 border-2 border-blue-200 rounded-xl focus:border-blue-500 focus:outline-none transition-all bg-blue-50/30 text-gray-800 placeholder-blue-400 shadow-sm"
                />
              </div>
            </div>
            <button
              type="submit"
              className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-bold py-4 px-6 rounded-xl transition-all duration-200 shadow-lg hover:shadow-xl transform hover:scale-105"
            >
              Next
            </button>
            {/* Divider and Sign Up CTA */}
<div className="relative mt-10">
  <div className="absolute inset-0 flex items-center">
    <div className="w-full border-t border-blue-200"></div>
  </div>
  <div className="relative flex justify-center text-sm">
    <span className="bg-white px-2 text-blue-500">New to DALScooter?</span>
  </div>
</div>

<button
  type="button"
  onClick={() => window.location.href = '/register'}
  className="mt-4 w-full border border-blue-500 text-blue-600 font-medium py-2 rounded-xl hover:bg-blue-50 transition-all"
>
  Create your account
</button>

          </form>
        )}

        {/* Step 2 */}
        {step === 2 && (
          <form onSubmit={handleStep2} className="space-y-6 relative z-10">
            <div className="text-center mb-6">
              <p className="text-blue-600 font-semibold">Answer security question</p>
            </div>
            <div className="space-y-5">
              <div className="bg-gradient-to-r from-blue-50 to-blue-100 border-2 border-blue-200 rounded-xl p-5 shadow-sm">
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center mr-3">
                    <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <p className="text-blue-800 font-semibold">{securityQuestion}</p>
                </div>
              </div>
              <input
                type="text"
                value={securityAnswer}
                onChange={(e) => setSecurityAnswer(e.target.value)}
                required
                placeholder="Your Answer"
                className="w-full px-4 py-4 border-2 border-blue-200 rounded-xl focus:border-blue-500 focus:outline-none transition-all bg-blue-50/30 text-gray-800 placeholder-blue-400 shadow-sm"
              />
            </div>
            <button
              type="submit"
              className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-bold py-4 px-6 rounded-xl transition-all duration-200 shadow-lg hover:shadow-xl transform hover:scale-105"
            >
              Next
            </button>
          </form>
        )}

        {/* Step 3 */}
        {step === 3 && (
          <form onSubmit={handleStep3} className="space-y-6 relative z-10">
            <div className="text-center mb-6">
              <p className="text-blue-600 font-semibold">Decode the encrypted text</p>
            </div>
            <div className="space-y-5">
              <div className="bg-gradient-to-r from-blue-50 to-blue-100 border-2 border-blue-200 rounded-xl p-5 shadow-sm">
                <p className="text-sm text-blue-600 mb-2 font-medium">Encrypted Text:</p>
                <p className="text-2xl font-mono font-bold text-blue-800 tracking-widest text-center py-2">{caesarChallenge}</p>
              </div>
              <input
                type="text"
                value={decodedWord}
                onChange={(e) => setDecodedWord(e.target.value.toUpperCase())}
                required
                placeholder="Decoded Word"
                className="w-full px-4 py-4 border-2 border-blue-200 rounded-xl focus:border-blue-500 focus:outline-none transition-all bg-blue-50/30 text-gray-800 placeholder-blue-400 shadow-sm text-center font-mono tracking-wider text-lg"
              />
              <div className="bg-blue-50 border-l-4 border-blue-400 p-4 rounded-r-xl">
                <div className="flex items-center">
                  <svg className="w-5 h-5 text-blue-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                  </svg>
                  <p className="text-sm text-blue-700">
                    Hint: This appears to be a Caesar cipher. Try shifting each letter by a certain number of positions.
                  </p>
                </div>
              </div>
            </div>
            <button
              type="submit"
              className="w-full bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white font-bold py-4 px-6 rounded-xl transition-all duration-200 shadow-lg hover:shadow-xl transform hover:scale-105"
            >
              Complete Login
            </button>
          </form>
        )}
      </div>
    </div>
  );
}