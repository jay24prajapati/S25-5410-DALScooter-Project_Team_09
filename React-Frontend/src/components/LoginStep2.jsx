import React from 'react';

const LoginStep2 = ({ question, answer, setAnswer, onNext }) => {
  const handleSubmit = (e) => {
    e.preventDefault();
    // TODO: Validate answer from backend
    onNext();
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3>Step 2: Security Question</h3>
      <p className="question-display">{question}</p>
      <div className="form-group">
        <label>Answer</label>
        <input
          type="text"
          value={answer}
          onChange={(e) => setAnswer(e.target.value)}
          required
        />
      </div>
      <button type="submit" className="btn btn-primary">
        Next
      </button>
    </form>
  );
};

export default LoginStep2;
