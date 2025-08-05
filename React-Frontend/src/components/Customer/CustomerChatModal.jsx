// src/components/Customer/CustomerChatModal.jsx
import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerChatModal({ bookingId, onClose }) {
  const [messages, setMessages] = useState([]);
  const [bookingInfo, setBookingInfo] = useState(null);
  const [newMsg, setNewMsg] = useState('');
  const token = localStorage.getItem('idToken');

  const fetchMessages = async () => {
    try {
      const res = await axios.get(`${API_BASE}/bookings/${bookingId}/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMessages(res.data.messages || []);
      setBookingInfo(res.data.booking_info || null);
    } catch (err) {
      console.error('Failed to fetch messages:', err);
    }
  };

  const sendMessage = async () => {
    if (!newMsg.trim()) return;
    try {
      await axios.post(
        `${API_BASE}/messages`,
        {
          booking_id: bookingId,
          content: newMsg
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );
      setNewMsg('');
      fetchMessages();
    } catch (err) {
      console.error('Failed to send message:', err);
    }
  };

  useEffect(() => {
    if (bookingId) fetchMessages();
  }, [bookingId]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex justify-center items-center z-50">
      <div className="bg-white w-full max-w-lg rounded-xl shadow-xl p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-bold">
            Chat with Franchise
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-red-500 text-xl">&times;</button>
        </div>

        {bookingInfo && (
          <div className="text-sm text-gray-600 mb-4">
            <p><strong>Bike:</strong> {bookingInfo.bike_type}</p>
            <p><strong>Date:</strong> {bookingInfo.date}</p>
            <p><strong>Status:</strong> {bookingInfo.status}</p>
          </div>
        )}

        <div className="h-64 overflow-y-auto space-y-2 mb-4 pr-2">
          {messages.map(msg => (
            <div
              key={msg.message_id}
              className={`p-2 rounded-lg w-fit max-w-xs ${
                msg.sender === 'CUSTOMER'
                  ? 'bg-blue-100 ml-auto text-right'
                  : 'bg-gray-100 mr-auto text-left'
              }`}
            >
              <div>{msg.content}</div>
              <div className="text-xs text-gray-500 mt-1">
                {new Date(msg.createdAt).toLocaleString()}
              </div>
            </div>
          ))}
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={newMsg}
            onChange={(e) => setNewMsg(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
            className="flex-1 border p-2 rounded-lg"
            placeholder="Type your message..."
          />
          <button
            onClick={sendMessage}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            Send
          </button>
        </div>
      </div>
    </div>
  );
}
