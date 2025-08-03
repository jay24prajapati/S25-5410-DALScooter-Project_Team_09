import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function MyBookings({ token }) {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchBookings = async () => {
    try {
      const res = await axios.get(`${API_BASE}/bookings`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      setBookings(res.data);
    } catch (err) {
      console.error('Error fetching bookings:', err);
    } finally {
      setLoading(false);
    }
  };

  const cancelBooking = async (booking_id) => {
    if (!window.confirm("Are you sure you want to cancel this booking?")) return;

    try {
      await axios.delete(`${API_BASE}/bookings/${booking_id}`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      setBookings(prev => prev.filter(b => b.booking_id !== booking_id));
      alert("Booking canceled successfully.");
    } catch (err) {
      console.error('Cancel error:', err);
      alert("Failed to cancel booking.");
    }
  };

  useEffect(() => {
    fetchBookings();
  }, []);

  return (
    <div>
      <h2 className="text-xl font-bold text-blue-800 mb-6">My Bookings</h2>

      {loading ? (
        <p className="text-blue-600">Loading bookings...</p>
      ) : bookings.length === 0 ? (
        <p className="text-gray-500">No bookings found.</p>
      ) : (
        <div className="space-y-4">
          {bookings.map((b) => (
            <div
              key={b.booking_id}
              className="bg-white p-5 shadow rounded-lg border border-blue-100"
            >
              <div className="flex justify-between items-center mb-2">
                <div>
                  <p className="font-semibold text-gray-800">
                    Scooter ID: <span className="text-blue-600">{b.bike_id.slice(0, 6)}...</span>
                  </p>
                  <p className="text-sm text-gray-500">Date: {b.date}</p>
                  <p className="text-sm text-gray-500">Rate: ${b.dailyRate}</p>
                </div>
                <div className="text-right">
                  <p
                    className={`font-semibold text-sm ${
                      b.status === 'CONFIRMED'
                        ? 'text-green-600'
                        : b.status === 'CANCELLED'
                        ? 'text-red-600'
                        : 'text-gray-600'
                    }`}
                  >
                    {b.status}
                  </p>
                  <p className="text-xs text-gray-400">#{b.booking_id.slice(0, 8)}...</p>
                </div>
              </div>

              {b.accessCode && (
                <p className="text-sm font-mono text-gray-700">
                  Access Code: <span className="bg-gray-100 px-2 py-1 rounded">{b.accessCode}</span>
                </p>
              )}

              <div className="mt-3 text-right">
                <button
                  onClick={() => cancelBooking(b.booking_id)}
                  className="text-sm bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded shadow"
                >
                  Cancel Booking
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
