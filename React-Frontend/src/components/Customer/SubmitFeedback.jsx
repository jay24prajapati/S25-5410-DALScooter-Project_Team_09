import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function SubmitFeedbackFromBookings() {
  const [bookings, setBookings] = useState([]);
  const [selectedBookingId, setSelectedBookingId] = useState('');
  const [bikeId, setBikeId] = useState('');
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState('');
  const [loading, setLoading] = useState(false);

  const token = localStorage.getItem('idToken');

  useEffect(() => {
    const fetchBookings = async () => {
      try {
        const res = await axios.get(`${API_BASE}/bookings`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        const eligible = res.data.filter(b =>
          ['CONFIRMED', 'COMPLETED', 'FINISHED'].includes(b.status)
        );

        setBookings(eligible);
      } catch (err) {
        console.error('Error fetching bookings:', err);
        toast.error('Failed to load bookings.');
      }
    };

    fetchBookings();
  }, []);

  const handleBookingSelect = (booking_id) => {
    setSelectedBookingId(booking_id);
    const selected = bookings.find(b => b.booking_id === booking_id);
    if (selected) {
      setBikeId(selected.bike_id);
    }
  };

  const handleFeedbackSubmit = async () => {
    if (!selectedBookingId || !bikeId || !comment.trim()) {
      toast.error('Please select a booking and write a comment.');
      return;
    }

    try {
      setLoading(true);
      const res = await axios.post(
        `${API_BASE}/bikes/${bikeId}/feedback`,
        {
          booking_id: selectedBookingId,
          rating: Number(rating),
          comment,
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      toast.success(res.data.message || 'Feedback submitted successfully!');
      setRating(5);
      setComment('');
      setSelectedBookingId('');
      setBikeId('');
    } catch (err) {
      console.error('Feedback error:', err);
      toast.error('Failed to submit feedback');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md max-w-xl mx-auto mt-6">
      <h2 className="text-xl font-semibold mb-4">Submit Feedback for a Booking</h2>

      <label className="block mb-2 font-medium">Select Booking:</label>
      <select
        value={selectedBookingId}
        onChange={(e) => handleBookingSelect(e.target.value)}
        className="border rounded-md px-3 py-2 w-full mb-4"
      >
        <option value="">-- Select a Booking --</option>
        {bookings.map((b) => (
          <option key={b.booking_id} value={b.booking_id}>
            {b.booking_id.slice(0, 8)} | {b.date} | ${b.dailyRate} | {b.status}
          </option>
        ))}
      </select>

      {selectedBookingId && (
        <>
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
        </>
      )}
    </div>
  );
}
