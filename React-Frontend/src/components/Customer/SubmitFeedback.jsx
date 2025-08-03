// src/components/Customer/SubmitFeedback.jsx
import React, { useState } from 'react';
import axios from 'axios';
const API_BASE_URL = import.meta.env.VITE_API_BASE;
import { toast } from 'react-toastify';

const SubmitFeedback = ({ bookingId, bikeId }) => {
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState('');
  const [loading, setLoading] = useState(false);

  const handleFeedbackSubmit = async () => {
    if (!comment.trim()) {
      toast.error('Please enter your feedback comment.');
      return;
    }

    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      const res = await axios.post(
        `${API_BASE_URL}/bikes/${bikeId}/feedback`,
        {
          booking_id: bookingId,
          rating: Number(rating),
          comment,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      toast.success(res.data.message || 'Feedback submitted successfully!');
      setRating(5);
      setComment('');
    } catch (err) {
      console.error('Feedback error:', err);
      toast.error('Failed to submit feedback');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md max-w-xl mx-auto mt-6">
      <h2 className="text-xl font-semibold mb-4">Submit Feedback</h2>

      <label className="block mb-2 font-medium">Rating:</label>
      <select
        value={rating}
        onChange={(e) => setRating(e.target.value)}
        className="border rounded-md px-3 py-2 w-full mb-4"
      >
        {[5, 4, 3, 2, 1].map((val) => (
          <option key={val} value={val}>{val} Star{val > 1 ? 's' : ''}</option>
        ))}
      </select>

      <label className="block mb-2 font-medium">Comment:</label>
      <textarea
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        className="border rounded-md px-3 py-2 w-full h-24 mb-4"
        placeholder="Share your ride experience..."
      />

      <button
        onClick={handleFeedbackSubmit}
        disabled={loading}
        className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md disabled:opacity-50"
      >
        {loading ? 'Submitting...' : 'Submit Feedback'}
      </button>
    </div>
  );
};

export default SubmitFeedback;
