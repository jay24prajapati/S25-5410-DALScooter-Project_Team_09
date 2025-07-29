import React, { useState } from 'react';

// LoginStep1 Component
function LoginStep1({ email, password, setEmail, setPassword, onNext }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    if (email && password) {
      onNext();
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center mb-6">
        <div className="flex items-center justify-center space-x-2 mb-4">
          <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold">1</div>
          <div className="w-12 h-1 bg-blue-200"></div>
          <div className="w-8 h-8 bg-blue-200 text-blue-400 rounded-full flex items-center justify-center font-bold">2</div>
          <div className="w-12 h-1 bg-blue-200"></div>
          <div className="w-8 h-8 bg-blue-200 text-blue-400 rounded-full flex items-center justify-center font-bold">3</div>
        </div>
        <p className="text-blue-600 font-medium">Enter your credentials</p>
      </div>

      <div className="space-y-4">
        <div className="space-y-2">
          <label className="block text-sm font-semibold text-blue-700">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
            placeholder="Enter your email"
          />
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-semibold text-blue-700">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
            placeholder="Enter your password"
          />
        </div>
      </div>

      <button
        onClick={handleSubmit}
        className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
      >
        Continue
      </button>
    </div>
  );
}

// LoginStep2 Component
function LoginStep2({ question, answer, setAnswer, onNext }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    if (answer) {
      onNext();
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center mb-6">
        <div className="flex items-center justify-center space-x-2 mb-4">
          <div className="w-8 h-8 bg-blue-300 text-white rounded-full flex items-center justify-center font-bold">✓</div>
          <div className="w-12 h-1 bg-blue-300"></div>
          <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold">2</div>
          <div className="w-12 h-1 bg-blue-200"></div>
          <div className="w-8 h-8 bg-blue-200 text-blue-400 rounded-full flex items-center justify-center font-bold">3</div>
        </div>
        <p className="text-blue-600 font-medium">Answer security question</p>
      </div>

      <div className="space-y-4">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-blue-800 font-medium">{question}</p>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-semibold text-blue-700">Your Answer</label>
          <input
            type="text"
            value={answer}
            onChange={(e) => setAnswer(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
            placeholder="Enter your answer"
          />
        </div>
      </div>

      <button
        onClick={handleSubmit}
        className="w-full bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
      >
        Continue
      </button>
    </div>
  );
}

// LoginStep3 Component
function LoginStep3({ encryptedText, decodedWord, setDecodedWord, onComplete }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    if (decodedWord) {
      onComplete();
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center mb-6">
        <div className="flex items-center justify-center space-x-2 mb-4">
          <div className="w-8 h-8 bg-blue-300 text-white rounded-full flex items-center justify-center font-bold">✓</div>
          <div className="w-12 h-1 bg-blue-300"></div>
          <div className="w-8 h-8 bg-blue-300 text-white rounded-full flex items-center justify-center font-bold">✓</div>
          <div className="w-12 h-1 bg-blue-300"></div>
          <div className="w-8 h-8 bg-blue-500 text-white rounded-full flex items-center justify-center font-bold">3</div>
        </div>
        <p className="text-blue-600 font-medium">Decode the encrypted text</p>
      </div>

      <div className="space-y-4">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-600 mb-2">Encrypted Text:</p>
          <p className="text-xl font-mono font-bold text-blue-800 tracking-widest">{encryptedText}</p>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-semibold text-blue-700">Decoded Word</label>
          <input
            type="text"
            value={decodedWord}
            onChange={(e) => setDecodedWord(e.target.value)}
            required
            className="w-full px-4 py-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none transition-colors bg-blue-50/30 text-gray-800 placeholder-blue-300"
            placeholder="Enter the decoded word"
          />
        </div>

        <div className="bg-blue-50 border-l-4 border-blue-400 p-3">
          <p className="text-xs text-blue-600">
            Hint: This appears to be a Caesar cipher. Try shifting each letter by a certain number of positions.
          </p>
        </div>
      </div>

      <button
        onClick={handleSubmit}
        className="w-full bg-gradient-to-r from-green-500 to-green-600 hover:from-green-600 hover:to-green-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-200 transform hover:scale-105 shadow-lg hover:shadow-xl"
      >
        Complete Login
      </button>
    </div>
  );
}

// Main LoginPage Component
export default function LoginPage() {
  const [step, setStep] = useState(1);

  // Step 1 state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // Step 2 state
  const [securityAnswer, setSecurityAnswer] = useState('');
  const securityQuestion = "What is your pet's name?"; // Replace with dynamic if needed

  // Step 3 state
  const [decodedWord, setDecodedWord] = useState('');
  const encryptedText = 'JXU EHTYZ'; // Replace with backend-generated challenge

  const handleNext = () => setStep((prev) => prev + 1);
  const handleComplete = () => {
    alert('Authentication Successful!');
    // redirect or show success
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-xl p-8 w-full max-w-md border border-blue-200">
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-blue-800 mb-2">3-Factor Login</h2>
          <div className="w-16 h-1 bg-gradient-to-r from-blue-400 to-blue-600 mx-auto rounded-full"></div>
        </div>

        {step === 1 && (
          <LoginStep1
            email={email}
            password={password}
            setEmail={setEmail}
            setPassword={setPassword}
            onNext={handleNext}
          />
        )}

        {step === 2 && (
          <LoginStep2
            question={securityQuestion}
            answer={securityAnswer}
            setAnswer={setSecurityAnswer}
            onNext={handleNext}
          />
        )}

        {step === 3 && (
          <LoginStep3
            encryptedText={encryptedText}
            decodedWord={decodedWord}
            setDecodedWord={setDecodedWord}
            onComplete={handleComplete}
          />
        )}
      </div>
    </div>
  );
}