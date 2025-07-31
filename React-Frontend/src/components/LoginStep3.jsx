import React from 'react';

const LoginStep3 = ({ encryptedText, decodedWord, setDecodedWord, onComplete }) => {
  const handleSubmit = (e) => {
    e.preventDefault();
    // TODO: Validate decoded word
    onComplete();
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3>Step 3: Caesar Cipher</h3>
      <p className="challenge-display">ENCRYPTED: {encryptedText}</p>
      <div className="form-group">
        <label>Decoded Word</label>
        <input
          type="text"
          value={decodedWord}
          onChange={(e) => setDecodedWord(e.target.value.toUpperCase())}
          required
        />
      </div>
      <button type="submit" className="btn btn-success">
        Login
      </button>
    </form>
  );
};

export default LoginStep3;
