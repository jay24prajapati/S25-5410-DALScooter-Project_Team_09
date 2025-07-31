import React from 'react';

const LoginStep1 = ({ email, password, setEmail, setPassword, onNext }) => {
  const handleSubmit = (e) => {
    e.preventDefault();
    // TODO: Validate via Cognito
    onNext();
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3>Step 1: Cognito Login</h3>
      <div className="form-group">
        <label>Email</label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </div>
      <div className="form-group">
        <label>Password</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>
      <button type="submit" className="btn btn-primary">
        Next
      </button>
    </form>
  );
};

export default LoginStep1;
