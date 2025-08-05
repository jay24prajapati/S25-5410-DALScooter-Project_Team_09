import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerConversationList({ onOpenChat }) {
  const [bookings, setBookings] = useState([]);
  const token = localStorage.getItem('idToken');

  useEffect(() => {
    const fetchBookings = async () => {
      try {
        const res = await axios.get(`${API_BASE}/bookings`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const confirmed = res.data.filter(b => b.status === 'CONFIRMED');
        setBookings(confirmed);
      } catch (err) {
        console.error('Error fetching bookings:', err);
        setBookings([]);
      }
    };
    fetchBookings();
  }, []);

  return (
    <div className="bg-white p-4 rounded-lg shadow">
      <h3 className="font-bold text-lg mb-2">Your Conversations</h3>
      <ul className="space-y-2 max-h-80 overflow-y-auto">
        {bookings.map((b) => (
          <li
            key={b.booking_id}
            className="cursor-pointer hover:bg-blue-50 p-2 rounded border"
            onClick={() => onOpenChat(b.booking_id)}
          >
            <div className="text-sm font-semibold text-blue-800">
              Booking: {b.booking_id.slice(0, 8)}
            </div>
            <div className="text-xs text-gray-600">
              Date: {new Date(b.date).toLocaleDateString()} | Rate: ${b.dailyRate}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
