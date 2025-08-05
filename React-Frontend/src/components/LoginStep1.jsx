import React, { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';

const LoginStep1 = ({ email, password, setEmail, setPassword, onNext }) => {
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    // TODO: Validate via Cognito
    onNext();
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3 className="text-xl font-semibold mb-4">Step 1: Cognito Login</h3>

      {/* Email */}
      <div className="form-group mb-4">
        <label className="block mb-1 text-sm text-gray-700">Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          className="w-full px-4 py-2 border rounded-md bg-gray-50"
          placeholder="Enter your email"
        />
      </div>

      {/* Password */}
      <div className="form-group mb-6 relative">
        <label className="block mb-1 text-sm text-gray-700">Password</label>
        <input
          type={showPassword ? 'text' : 'password'}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          className="w-full px-4 py-2 pr-10 border rounded-md bg-gray-50"
          placeholder="Enter your password"
        />
        <div
          className="absolute top-9 right-3 cursor-pointer text-gray-500"
          onClick={() => setShowPassword((prev) => !prev)}
        >
          {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
        </div>
      </div>

      <button
        type="submit"
        className="w-full bg-blue-600 text-white py-2 rounded-md font-medium hover:bg-blue-700 transition"
      >
        Next
      </button>
    </form>
  );
};

export default LoginStep1;
