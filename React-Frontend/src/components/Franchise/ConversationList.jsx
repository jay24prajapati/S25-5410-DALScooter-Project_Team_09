import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function ConversationList({ onOpenChat }) {
  const [conversations, setConversations] = useState([]);

  useEffect(() => {
    axios.get(`${import.meta.env.VITE_API_BASE}/franchise/conversations`)
      .then(res => setConversations(res.data))
      .catch(err => console.error('Failed to fetch conversations:', err));
  }, []);

  return (
    <div className="p-4 bg-white rounded-xl shadow-lg">
      <h2 className="text-xl font-bold mb-4">Customer Messages</h2>
      {conversations.map((conv) => (
        <div key={conv.customer_id} className="p-4 border-b cursor-pointer hover:bg-blue-50" onClick={() => onOpenChat(conv.lastMessage.booking_id)}>
          <div className="font-semibold">{conv.customer_email}</div>
          <div className="text-gray-600 text-sm truncate">{conv.lastMessage.content}</div>
          <div className="text-xs text-gray-400">From: {conv.lastMessage.sender} | {new Date(conv.lastMessage.createdAt).toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}
