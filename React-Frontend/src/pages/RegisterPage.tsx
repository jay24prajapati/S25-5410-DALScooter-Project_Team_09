import React, { useState } from 'react';

export default function RegisterPage() {
  // Mock navigate function for demo purposes
  const navigate = (path) => {
    console.log(`Navigating to: ${path}`);
    alert(`Would navigate to: ${path}`);
  };

  const [form, setForm] = useState({
    email: '',
    password: '',
    userType: '',
    securityQuestion: '',
    securityAnswer: '',
  });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    // TODO: Call registration API
    navigate('/verify-email');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-xl p-8 w-full max-w-md border border-blue-200">
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-blue-800 mb-2">User Registration</h2>
          <div className="w-16 h-1 bg-gradient-to-r from-blue-400 to-blue-600 mx-auto rounded-full"></div>
        </div>
        
        <div className="space-y-6">
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-blue-700">Email</label>
            <input 
              type="email" 
              name="email" 
              value={form.email} 
              onChange={handleChange} 
              required 
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
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
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
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
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800"
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
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800"
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
              className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
              placeholder="Enter your answer"
            />
          </div>

          <button 
            type="submit" 
            onClick={handleSubmit}
            className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
          >
            Register
          </button>
        </div>
      </div>
    </div>
  );
}