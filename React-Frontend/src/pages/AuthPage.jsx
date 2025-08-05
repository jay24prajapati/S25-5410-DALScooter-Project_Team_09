import React, { useState } from 'react';
import '../styles/AuthPage.css';

export default function AuthPage() {
  const [activeTab, setActiveTab] = useState('register');

  const renderTabContent = () => {
    switch (activeTab) {
      case 'register':
        return (
          <div className="form-container">
            <h2>User Registration</h2>
            <form id="register-form">
              <div className="form-group">
                <label>Email</label>
                <input type="email" placeholder="your.email@dal.ca" required />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input type="password" placeholder="Minimum 8 characters" required />
              </div>
              <div className="form-group">
                <label>User Type</label>
                <select required>
                  <option value="">Select user type...</option>
                  <option value="customer">Customer</option>
                  <option value="franchise">Franchise Operator</option>
                </select>
              </div>
              <div className="form-group">
                <label>Security Question</label>
                <select required>
                  <option value="">Choose a security question...</option>
                  <option>What is your favorite color?</option>
                  <option>What city were you born in?</option>
                  <option>What is your pet's name?</option>
                  <option>What is your favorite food?</option>
                  <option>What was your first car?</option>
                </select>
              </div>
              <div className="form-group">
                <label>Security Answer</label>
                <input type="text" placeholder="Your answer (case insensitive)" required />
              </div>
              <button type="submit" className="btn btn-primary">Register</button>
            </form>
          </div>
        );

      case 'verify':
        return (
          <div className="form-container">
            <h2>Email Verification</h2>
            <form id="verify-form">
              <div className="form-group">
                <label>Email</label>
                <input type="email" placeholder="your.email@dal.ca" required />
              </div>
              <div className="form-group">
                <label>Verification Code</label>
                <input type="text" placeholder="6-digit code" required />
              </div>
              <button type="submit" className="btn btn-success">Verify Email</button>
            </form>
          </div>
        );

      case 'login':
        return (
          <div className="form-container">
            <h2>3-Factor Login</h2>

            {/* Step 1: Cognito */}
            <div className="auth-step">
              <h3>Step 1: Cognito Login</h3>
              <form id="login-step1-form">
                <div className="form-group">
                  <label>Email</label>
                  <input type="email" placeholder="your.email@dal.ca" required />
                </div>
                <div className="form-group">
                  <label>Password</label>
                  <input type="password" placeholder="Your password" required />
                </div>
                <button type="submit" className="btn btn-primary">Next Step</button>
              </form>
            </div>

            {/* Step 2: Security Question */}
            <div className="auth-step">
              <h3>Step 2: Security Question</h3>
              <div className="question-display">What is your pet's name?</div>
              <form id="login-step2-form">
                <div className="form-group">
                  <label>Security Answer</label>
                  <input type="text" placeholder="Enter your answer" required />
                </div>
                <button type="submit" className="btn btn-primary">Next Step</button>
              </form>
            </div>

            {/* Step 3: Caesar Cipher */}
            <div className="auth-step">
              <h3>Step 3: Caesar Cipher Challenge</h3>
              <div className="challenge-display">ENCRYPTED: JXU EHTYZ</div>
              <form id="login-step3-form">
                <div className="form-group">
                  <label>Decoded Word</label>
                  <input type="text" placeholder="Enter the decoded word" style={{ textTransform: 'uppercase' }} required />
                </div>
                <button type="submit" className="btn btn-success">Complete Authentication</button>
              </form>
            </div>

            {/* Success Panel */}
            <div className="auth-step success-panel">
              <h3>Authentication Successful!</h3>
              <button className="btn btn-secondary">Login Again</button>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="auth-page">
      <header>
        <h1>DALScooter</h1>
        <p>Serverless Authentication System</p>
      </header>

      <div className="tabs">
        <button onClick={() => setActiveTab('register')} className={activeTab === 'register' ? 'active' : ''}>Register</button>
        <button onClick={() => setActiveTab('verify')} className={activeTab === 'verify' ? 'active' : ''}>Verify Email</button>
        <button onClick={() => setActiveTab('login')} className={activeTab === 'login' ? 'active' : ''}>Login</button>
      </div>

      {renderTabContent()}
    </div>
  );
}
