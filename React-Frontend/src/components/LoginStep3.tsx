import React from 'react';

interface Props {
  encryptedText: string;
  decodedWord: string;
  setDecodedWord: (value: string) => void;
  onComplete: () => void;
}

const LoginStep3: React.FC<Props> = ({ encryptedText, decodedWord, setDecodedWord, onComplete }) => {
  const handleSubmit = (e: React.FormEvent) => {
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
      <button type="submit" className="btn btn-success">Login</button>
    </form>
  );
};

export default LoginStep3;

