import React, { useEffect, useState, useRef } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerChatModal({ bookingId, onClose }) {
  const [messages, setMessages] = useState([]);
  const [bookingInfo, setBookingInfo] = useState(null);
  const [newMsg, setNewMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const messagesEndRef = useRef(null);
  const token = localStorage.getItem('idToken');

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const fetchMessages = async () => {
    setIsLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/bookings/${bookingId}/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setMessages(res.data.messages || []);
      setBookingInfo(res.data.booking_info || null);
    } catch (err) {
      console.error('Failed to fetch messages:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const sendMessage = async () => {
    if (!newMsg.trim() || isSending) return;
    
    setIsSending(true);
    const tempMessage = newMsg;
    setNewMsg('');
    
    try {
      await axios.post(
        `${API_BASE}/messages`,
        {
          booking_id: bookingId,
          content: tempMessage,
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      fetchMessages();
    } catch (err) {
      console.error('Failed to send message:', err);
      setNewMsg(tempMessage); // Restore message on error
    } finally {
      setIsSending(false);
    }
  };

  useEffect(() => {
    if (bookingId) fetchMessages();
  }, [bookingId]);

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'confirmed': return 'text-green-600 bg-green-50';
      case 'pending': return 'text-yellow-600 bg-yellow-50';
      case 'cancelled': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex justify-center items-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-white w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden animate-in slide-in-from-bottom-4 duration-300">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white p-6">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-xl font-bold mb-1">Chat with Franchise</h2>
              <p className="text-blue-100 text-sm">Booking ID: #{bookingId}</p>
            </div>
            <button 
              onClick={onClose} 
              className="text-white/80 hover:text-white hover:bg-white/20 rounded-full p-2 transition-all duration-200"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Booking Info */}
        {bookingInfo && (
          <div className="bg-gray-50 border-b p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="flex items-center space-x-2">
                <div className="bg-blue-100 p-2 rounded-lg">
                  <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">Bike Type</p>
                  <p className="font-semibold text-gray-900">{bookingInfo.bike_type}</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <div className="bg-green-100 p-2 rounded-lg">
                  <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">Date</p>
                  <p className="font-semibold text-gray-900">{bookingInfo.date}</p>
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <div className="bg-purple-100 p-2 rounded-lg">
                  <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <p className="text-xs text-gray-500 uppercase tracking-wide">Status</p>
                  <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(bookingInfo.status)}`}>
                    {bookingInfo.status}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Chat History */}
        <div className="h-96 overflow-y-auto p-4 space-y-4 bg-gray-50">
          {isLoading ? (
            <div className="flex justify-center items-center h-full">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-500">
              <svg className="w-12 h-12 mb-3 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
              <p className="text-sm">No messages yet</p>
              <p className="text-xs">Start a conversation with the franchise</p>
            </div>
          ) : (
            messages.map((msg, index) => (
              <div
                key={msg.message_id}
                className={`flex ${msg.sender === 'CUSTOMER' ? 'justify-end' : 'justify-start'} animate-in slide-in-from-bottom-2 duration-300`}
                style={{ animationDelay: `${index * 50}ms` }}
              >
                <div
                  className={`max-w-xs md:max-w-md p-3 rounded-2xl shadow-sm ${
                    msg.sender === 'CUSTOMER'
                      ? 'bg-blue-600 text-white rounded-br-md'
                      : 'bg-white text-gray-800 rounded-bl-md border'
                  }`}
                >
                  <div className="break-words">{msg.content}</div>
                  <div className={`text-xs mt-1 ${
                    msg.sender === 'CUSTOMER' ? 'text-blue-100' : 'text-gray-500'
                  }`}>
                    {new Date(msg.createdAt).toLocaleString()}
                  </div>
                </div>
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Section */}
        <div className="bg-white border-t p-4">
          <div className="flex items-end space-x-3">
            <div className="flex-1 relative">
              <textarea
                value={newMsg}
                onChange={(e) => setNewMsg(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                  }
                }}
                className="w-full border border-gray-300 rounded-xl px-4 py-3 pr-12 resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 max-h-32"
                placeholder="Type your message... (Press Enter to send)"
                rows="1"
                style={{ minHeight: '44px' }}
              />
              <div className="absolute right-3 bottom-3 text-xs text-gray-400">
                {newMsg.length}/1000
              </div>
            </div>
            <button
              onClick={sendMessage}
              disabled={!newMsg.trim() || isSending}
              className="bg-blue-600 text-white p-3 rounded-xl hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
            >
              {isSending ? (
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
              )}
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-2 text-center">
            Press Shift+Enter for new line
          </p>
        </div>
      </div>
    </div>
  );
}