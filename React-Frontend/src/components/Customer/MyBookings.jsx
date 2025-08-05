import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';
import { format } from 'date-fns';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function MyBookings() {
  const [bookings, setBookings] = useState([]);
  const [bikes, setBikes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [cancellingId, setCancellingId] = useState('');
  const [lookupRef, setLookupRef] = useState('');

  const token = localStorage.getItem('idToken');

  const fetchBookings = async () => {
    try {
      const res = await axios.get(`${API_BASE}/bookings`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setBookings(res.data);
    } catch (err) {
      console.error('Error fetching bookings:', err);
      toast.error('Failed to load bookings');
    } finally {
      setLoading(false);
    }
  };

  const fetchBikes = async () => {
    try {
      const res = await axios.get(`${API_BASE}/bikes`);
      setBikes(res.data);
    } catch (err) {
      console.error('Error fetching bikes:', err);
      toast.error('Failed to load bike data');
    }
  };

  useEffect(() => {
    fetchBookings();
    fetchBikes();
  }, []);

  const cancelBooking = async (booking_id) => {
    if (!window.confirm('Are you sure you want to cancel this booking?')) return;

    try {
      setCancellingId(booking_id);
      await axios.delete(`${API_BASE}/bookings/${booking_id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setBookings(prev =>
        prev.map(b =>
          b.booking_id === booking_id ? { ...b, status: 'CANCELLED' } : b
        )
      );
      toast.success('Booking cancelled.');
    } catch (err) {
      console.error('Cancel error:', err);
      toast.error('Failed to cancel booking.');
    } finally {
      setCancellingId('');
    }
  };

  const getBikeByBookingRef = (refId) => {
    const booking = bookings.find((b) => b.booking_id === refId);
    if (!booking) return null;
    const bike = bikes.find((b) => b.id === booking.bike_id);
    return { booking, bike };
  };

  const handleLookup = () => {
    const result = getBikeByBookingRef(lookupRef);
    if (result) {
      const { booking, bike } = result;
      alert(
        `Bike: ${bike?.model || 'Unknown'}\n` +
        `Date: ${format(new Date(booking.date), 'yyyy-MM-dd')}\n` +
        `Access Code: ${booking.accessCode || 'Not available yet'}\n` +
        `Booking Status: ${booking.status}`
      );
    } else {
      toast.warn('Booking reference not found.');
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-blue-800">My Bookings</h2>

      {/* Lookup Section */}
      <div className="bg-white p-5 rounded-xl shadow border border-blue-100">
        <h4 className="text-lg font-semibold text-blue-700 mb-2">Lookup by Booking Reference</h4>
        <div className="flex space-x-4">
          <input
            type="text"
            className="flex-1 p-3 border border-blue-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Enter Booking ID"
            value={lookupRef}
            onChange={(e) => setLookupRef(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleLookup()}
          />
          <button
            onClick={handleLookup}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
          >
            Lookup
          </button>
        </div>
      </div>

      {/* Bookings List */}
      {loading ? (
        <p className="text-blue-600">Loading bookings...</p>
      ) : bookings.length === 0 ? (
        <p className="text-gray-500">No bookings found.</p>
      ) : (
        <div className="space-y-4">
          {bookings.map((b) => {
            const bike = bikes.find((bk) => bk.id === b.bike_id);
            return (
              <div
                key={b.booking_id}
                className="bg-white p-5 shadow rounded-lg border border-blue-100"
              >
                <div className="flex justify-between items-center mb-2">
                  <div>
                    <p className="font-semibold text-gray-800">
                      {bike?.model || 'Unknown'} ({bike?.type || 'N/A'})
                    </p>
                    <p className="text-sm text-gray-500">
Date: {b.date}
                    </p>
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
                    <p className="text-xs text-gray-400">
                      #{b.booking_id.slice(0, 8)}...
                    </p>
                  </div>
                </div>

                {b.accessCode ? (
                  <p className="text-sm font-mono text-gray-700">
                    Access Code:{' '}
                    <span className="bg-gray-100 px-2 py-1 rounded">
                      {b.accessCode}
                    </span>
                  </p>
                ) : (
                  <p className="text-sm text-gray-400 italic">
                    Access code will be available on ride day.
                  </p>
                )}

                {b.status !== 'CANCELLED' && (
  <div className="mt-3 text-right">
    <button
      onClick={() => cancelBooking(b.booking_id)}
      disabled={cancellingId === b.booking_id}
      className="text-sm px-4 py-2 rounded shadow bg-red-500 hover:bg-red-600 text-white transition-all"
    >
      {cancellingId === b.booking_id ? 'Cancelling...' : 'Cancel Booking'}
    </button>
  </div>
)}

              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
