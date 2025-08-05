import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function ChatModal({ bookingId, onClose }) {
  const [messages, setMessages] = useState([]);
  const [newMsg, setNewMsg] = useState('');
  const API_BASE = import.meta.env.VITE_API_BASE;
  const token = localStorage.getItem('idToken');

  const [bookingInfo, setBookingInfo] = useState(null);

const fetchMessages = async () => {
  try {
    const res = await axios.get(`${API_BASE}/franchise/bookings/${bookingId}/messages`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    setMessages(res.data.messages || []);
    setBookingInfo(res.data.booking_info || null);
  } catch (err) {
    console.error('Error fetching messages:', err);
  }
};


  useEffect(() => {
    if (bookingId) fetchMessages();
  }, [bookingId]);

  const sendMessage = async () => {
    if (!newMsg.trim()) return;
    try {
      await axios.post(
        `${API_BASE}/messages`,
        {
          booking_id: bookingId,
          content: newMsg,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setNewMsg('');
      fetchMessages(); // Refresh chat
    } catch (err) {
      console.error('Error sending message:', err);
    }
  };

  return (
<div className="fixed inset-0 bg-gradient-to-br from-blue-200/60 to-indigo-200/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white w-full max-w-lg rounded-xl shadow-xl p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-bold">
  Chat with {bookingInfo?.customer_email || 'Customer'}
</h2>

          <button onClick={onClose} className="text-gray-500 hover:text-red-500">&times;</button>
        </div>

        <div className="h-64 overflow-y-auto space-y-2 mb-4">
          {messages.map(msg => (
            <div key={msg.message_id} className={`p-2 rounded-lg ${msg.sender === 'CUSTOMER' ? 'bg-gray-100 text-left' : 'bg-blue-100 text-right'}`}>
              <div>{msg.content}</div>
              <div className="text-xs text-gray-500">{new Date(msg.createdAt).toLocaleString()}</div>
            </div>
          ))}
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={newMsg}
            onChange={(e) => setNewMsg(e.target.value)}
            className="flex-1 border p-2 rounded-lg"
            placeholder="Type your message..."
            onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
          />
          <button onClick={sendMessage} className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">Send</button>
        </div>
      </div>
    </div>
  );
}
