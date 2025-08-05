import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function BookingSection() {
  const [bookings, setBookings] = useState([]);
  const [bikes, setBikes] = useState([]);
  const [lookupRef, setLookupRef] = useState('');

  const fetchBookings = async () => {
    try {
      const token = localStorage.getItem('idToken');
      const response = await axios.get(
        `${API_BASE}/franchise/bookings?status=CONFIRMED&dateFrom=2025-07-01&dateTo=2025-08-31`,
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      console.log('Bookings fetched:', response.data);

      const normalized = response.data.bookings.map(b => ({
        id: b.booking_id,
        bikeId: b.bike_id,
        customerId: b.customer_id,
        date: b.date,
        status: b.status,
        rate: b.dailyRate,
        accessCode: b.accessCode,
        createdAt: b.createdAt,
        customer: b.customer_id || 'Customer', // use customer_id for now
        startTime: '-',        // Placeholder
        endTime: '-'           // Placeholder
      }));

      setBookings(normalized);
    } catch (err) {
      console.error('Failed to fetch bookings:', err);
    }
  };

  const fetchBikes = async () => {
    try {
      const res = await axios.get(`${API_BASE}/bikes`);
      setBikes(res.data);
    } catch (err) {
      console.error('Failed to fetch bikes:', err);
    }
  };

  useEffect(() => {
    fetchBookings();
    fetchBikes();
  }, []);

  const getBikeByBookingRef = (refId) => {
    const booking = bookings.find((b) => b.id === refId);
    if (!booking) return null;
    const bike = bikes.find((b) => b.id === booking.bikeId);
    return { booking, bike };
  };

  const handleLookup = () => {
    const result = getBikeByBookingRef(lookupRef);
    if (result) {
      alert(
        `Bike: ${result.bike?.model || 'N/A'}\nDuration: ${result.booking.startTime} - ${result.booking.endTime}\nAccess Code: ${result.bike?.accessCode || 'N/A'}`
      );
    } else {
      alert('Booking reference not found');
    }
  };

  return (
    <div className="space-y-6">
      <h3 className="text-2xl font-bold text-blue-800">Booking Management</h3>

      <div className="bg-white rounded-xl shadow-lg border border-blue-100">
        {/* Booking Lookup */}
        <div className="p-6 border-b border-blue-100">
          <h4 className="text-lg font-semibold text-blue-700">Booking Reference Lookup</h4>
          <div className="mt-4 flex space-x-4">
            <input
              type="text"
              placeholder="Enter booking reference (UUID)"
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
        {/* Booking Table */}
<div className="overflow-x-auto">
  <table className="w-full">
    <thead className="bg-blue-50">
      <tr>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Booking ID</th>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Customer ID</th>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Date</th>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Rate</th>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Access Code</th>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Status</th>
        <th className="px-6 py-4 text-left text-blue-700 font-semibold">Created At</th>
      </tr>
    </thead>
    <tbody>
      {bookings.map((booking) => {
        const bike = bikes.find((b) => b.id === booking.bikeId);
        return (
          <tr key={booking.id} className="border-b border-blue-100 hover:bg-blue-50">
            <td className="px-6 py-4 font-mono text-blue-600">{booking.id}</td>
            <td className="px-6 py-4 text-sm">{booking.customerId}</td>
<td className="px-6 py-4">{booking.date}</td>
            <td className="px-6 py-4">${booking.rate.toFixed(2)}</td>
            <td className="px-6 py-4 font-mono text-blue-700">{booking.accessCode}</td>
            <td className="px-6 py-4">
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                booking.status === 'CONFIRMED'
                  ? 'bg-green-100 text-green-800'
                  : 'bg-blue-100 text-blue-800'
              }`}>
                {booking.status}
              </span>
            </td>
            <td className="px-6 py-4 text-sm text-gray-600">
              {new Date(booking.createdAt).toLocaleString()}
            </td>
          </tr>
        );
      })}
    </tbody>
  </table>
</div>

      </div>
    </div>
  );
}
