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
      toast.success('Booking cancelled successfully!');
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
    const bike = bikes.find((b) => b.bike_id === booking.bike_id);
    return { booking, bike };
  };

  const handleLookup = () => {
    const result = getBikeByBookingRef(lookupRef);
    if (result) {
      const { booking, bike } = result;
      alert(
        `Bike: ${bike?.type || 'Unknown'}\n` +
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
      <h3 className="text-2xl font-bold text-blue-800">My Bookings</h3>

      <div className="bg-white rounded-xl shadow-lg border border-blue-100">
        {/* Booking Lookup */}
        <div className="p-6 border-b border-blue-100">
          <h4 className="text-lg font-semibold text-blue-700">Booking Reference Lookup</h4>
          <div className="mt-4 flex space-x-4">
            <input
              type="text"
              placeholder="Enter booking reference"
              className="flex-1 p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
              value={lookupRef}
              onChange={(e) => setLookupRef(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleLookup()}
            />
            <button
              onClick={handleLookup}
              className="bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 transition-colors"
            >
              Lookup
            </button>
          </div>
        </div>

        {/* Booking Table */}
        {loading ? (
          <div className="p-8 text-center">
            <p className="text-blue-600">Loading bookings...</p>
          </div>
        ) : bookings.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-gray-500">No bookings found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-blue-50">
                <tr>
                  <th className="px-6 py-4 text-left text-blue-700 font-semibold">Bike Type</th>
                  <th className="px-6 py-4 text-left text-blue-700 font-semibold">Date</th>
                  <th className="px-6 py-4 text-left text-blue-700 font-semibold">Rate</th>
                  <th className="px-6 py-4 text-left text-blue-700 font-semibold">Access Code</th>
                  <th className="px-6 py-4 text-left text-blue-700 font-semibold">Status</th>
                  <th className="px-6 py-4 text-left text-blue-700 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody>
                {bookings.map((booking) => {
                  const bike = bikes.find((b) => b.bike_id === booking.bike_id);
                  return (
                    <tr key={booking.booking_id} className="border-b border-blue-100 hover:bg-blue-50">
                      <td className="px-6 py-4 font-semibold text-gray-800">
                        {bike?.type || 'Unknown'}
                      </td>
                      <td className="px-6 py-4">{booking.date}</td>
                      <td className="px-6 py-4">${booking.dailyRate}</td>
                      <td className="px-6 py-4 font-mono text-blue-700">
                        {booking.accessCode || 'Pending'}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                          booking.status === 'CONFIRMED'
                            ? 'bg-green-100 text-green-800'
                            : booking.status === 'CANCELLED'
                            ? 'bg-red-100 text-red-800'
                            : 'bg-blue-100 text-blue-800'
                        }`}>
                          {booking.status}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        {booking.status !== 'CANCELLED' && (
                          <button
                            onClick={() => cancelBooking(booking.booking_id)}
                            disabled={cancellingId === booking.booking_id}
                            className="text-sm px-3 py-1 rounded bg-red-500 hover:bg-red-600 text-white transition-all disabled:bg-gray-400"
                          >
                            {cancellingId === booking.booking_id ? 'Cancelling...' : 'Cancel'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
