// src/components/Customer/BookingMessages.jsx
import React, { useEffect, useState } from 'react';
import axios from 'axios';
const API_BASE_URL = import.meta.env.VITE_API_BASE;
const BookingMessages = ({ bookingId }) => {
  const [messages, setMessages] = useState([]);
  const [bookingInfo, setBookingInfo] = useState(null);
  const [newMessage, setNewMessage] = useState('');

  const fetchMessages = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get(`${API_BASE_URL}/bookings/${bookingId}/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMessages(res.data.messages);
      setBookingInfo(res.data.booking_info);
    } catch (err) {
      console.error('Error fetching messages:', err);
    }
  };

  const sendMessage = async () => {
    if (!newMessage.trim()) return;
    try {
      const token = localStorage.getItem('token');
      await axios.post(
        `${API_BASE_URL}/messages`,
        {
          booking_id: bookingId,
          content: newMessage,
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      setNewMessage('');
      fetchMessages(); // Refresh after sending
    } catch (err) {
      console.error('Error sending message:', err);
    }
  };

  useEffect(() => {
    fetchMessages();
  }, [bookingId]);

  return (
    <div className="p-6 bg-white shadow-md rounded-lg max-w-3xl mx-auto mt-6">
      <h2 className="text-xl font-bold mb-4">Messages for Booking ID: {bookingId}</h2>

      {bookingInfo && (
        <div className="mb-4 text-sm text-gray-700">
          <p><strong>Bike:</strong> {bookingInfo.bike_type}</p>
          <p><strong>Date:</strong> {bookingInfo.date}</p>
          <p><strong>Status:</strong> {bookingInfo.status}</p>
        </div>
      )}

      <div className="space-y-2 mb-4">
        {messages.map((msg) => (
          <div
            key={msg.message_id}
            className={`p-2 rounded-md ${msg.sender === 'CUSTOMER' ? 'bg-blue-100 text-right' : 'bg-gray-100 text-left'}`}
          >
            <p className="text-sm">{msg.content}</p>
            <p className="text-xs text-gray-500">{new Date(msg.createdAt).toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="flex space-x-2">
        <input
          type="text"
          placeholder="Type a message..."
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
          className="flex-1 border px-3 py-2 rounded-md"
        />
        <button
          onClick={sendMessage}
          className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
        >
          Send
        </button>
      </div>
    </div>
  );
};

export default BookingMessages;
