import React, { useState } from 'react';

export default function VerifyEmailPage() {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  
  // Mock navigate function for demo purposes
  const navigate = (path) => {
    console.log(`Navigating to: ${path}`);
    alert(`Would navigate to: ${path}`);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    // TODO: Call verify email API
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-xl p-8 w-full max-w-md border border-blue-200">
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-blue-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <h2 className="text-3xl font-bold text-blue-800 mb-2">Email Verification</h2>
          <div className="w-16 h-1 bg-gradient-to-r from-blue-400 to-blue-600 mx-auto rounded-full mb-4"></div>
          <p className="text-blue-600 text-sm">Please check your email and enter the verification code below</p>
        </div>
        
        <div className="space-y-6">
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-blue-700">Email</label>
            <input 
              type="email" 
              value={email} 
              onChange={(e) => setEmail(e.target.value)} 
              required 
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
              placeholder="Enter your email address"
            />
          </div>

          <div className="space-y-2">
            <label className="block text-sm font-semibold text-blue-700">Verification Code</label>
            <input 
              type="text" 
              value={code} 
              onChange={(e) => setCode(e.target.value)} 
              required 
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300 text-center text-xl font-mono tracking-widest"
              placeholder="Enter 6-digit code"
              maxLength={6}
            />
          </div>

          <div className="bg-blue-50 border-l-4 border-blue-400 p-4 rounded-r-lg">
            <div className="flex items-start">
              <svg className="w-5 h-5 text-blue-500 mt-0.5 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
              <div>
                <p className="text-sm text-blue-700 font-medium">Didn't receive the code?</p>
                <p className="text-xs text-blue-600 mt-1">Check your spam folder or click resend after 60 seconds</p>
              </div>
            </div>
          </div>

          <button 
            onClick={handleSubmit}
            className="w-full bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
          >
            Verify Email
          </button>

          <div className="text-center">
            <button 
              type="button"
              className="text-blue-600 hover:text-blue-800 text-sm font-medium underline transition-colors"
              onClick={() => alert('Resend verification code functionality')}
            >
              Resend verification code
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}