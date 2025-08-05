import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function ConversationList({ onOpenChat }) {
  const [bookings, setBookings] = useState([]);
  const API_BASE = import.meta.env.VITE_API_BASE;
  const token = localStorage.getItem('idToken');

  useEffect(() => {
    const fetchBookings = async () => {
      try {
        const res = await axios.get(
          `${API_BASE}/franchise/bookings?status=CONFIRMED&dateFrom=2025-07-01&dateTo=2025-08-31`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        setBookings(res.data.bookings || []); // ✅ fix: use res.data.bookings
      } catch (err) {
        console.error('Failed to load bookings:', err);
        setBookings([]); // fallback to empty array
      }
    };

    fetchBookings();
  }, []);

  return (
    <div className="bg-white p-4 rounded-lg shadow">
      <h3 className="font-bold text-lg mb-2">Customer Conversations</h3>
      <ul className="space-y-2 max-h-80 overflow-y-auto">
        {bookings.map((b) => (
          <li
            key={b.booking_id}
            className="cursor-pointer hover:bg-blue-50 p-2 rounded border"
            onClick={() => onOpenChat(b.booking_id)}
          >
            <div className="text-sm font-semibold">Booking: {b.booking_id.slice(0, 8)}</div>
            <div className="text-xs text-gray-600">Date: {b.date} | Rate: ${b.dailyRate}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
