import React from 'react';

interface Props {
  email: string;
  password: string;
  setEmail: (value: string) => void;
  setPassword: (value: string) => void;
  onNext: () => void;
}

const LoginStep1: React.FC<Props> = ({ email, password, setEmail, setPassword, onNext }) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // TODO: Validate via Cognito
    onNext();
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3>Step 1: Cognito Login</h3>
      <div className="form-group">
        <label>Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
      </div>
      <div className="form-group">
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>
      <button type="submit" className="btn btn-primary">Next</button>
    </form>
  );
};

export default LoginStep1;
