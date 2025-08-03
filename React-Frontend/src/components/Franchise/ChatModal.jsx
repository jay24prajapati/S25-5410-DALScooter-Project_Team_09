import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function ChatModal({ bookingId, onClose }) {
  const [messages, setMessages] = useState([]);
  const [newMsg, setNewMsg] = useState('');

  const fetchMessages = async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_BASE}/franchise/bookings/${bookingId}/messages`);
      setMessages(res.data.messages || []);
    } catch (err) {
      console.error('Error fetching messages:', err);
    }
  };

  useEffect(() => {
    if (bookingId) fetchMessages();
  }, [bookingId]);

  const sendMessage = async () => {
    if (!newMsg.trim()) return;
    await axios.post(`${import.meta.env.VITE_API_BASE}/messages`, {
      booking_id: bookingId,
      content: newMsg,
    });
    setNewMsg('');
    fetchMessages();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex justify-center items-center z-50">
      <div className="bg-white w-full max-w-lg rounded-xl shadow-xl p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-bold">Chat with Customer</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-red-500">&times;</button>
        </div>
        <div className="h-64 overflow-y-auto space-y-2 mb-4">
          {messages.map(msg => (
            <div key={msg.message_id} className={`p-2 rounded-lg ${msg.sender === 'CUSTOMER' ? 'bg-gray-100' : 'bg-blue-100 text-right'}`}>
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
          />
          <button onClick={sendMessage} className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">Send</button>
        </div>
      </div>
    </div>
  );
}
