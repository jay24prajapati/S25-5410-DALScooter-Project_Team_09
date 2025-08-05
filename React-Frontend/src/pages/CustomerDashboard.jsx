import React, { useEffect, useState } from 'react';
import axios from 'axios';
import CustomerProfile from '../components/Customer/CustomerProfile';
import MyBookings from '../components/Customer/MyBookings';
import SubmitFeedbackFromBookings from '../components/Customer/SubmitFeedback';
import CustomerConversationList from '../components/Customer/CustomerConversationList';
import CustomerChatModal from '../components/Customer/CustomerChatModal';
import { toast } from 'react-toastify';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerDashboard() {
  const [currentUser, setCurrentUser] = useState(null);
  const [bikes, setBikes] = useState([]);
  const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('booking');
  const [chatBookingId, setChatBookingId] = useState(null);

  const getAuthToken = () => {
    return (
      localStorage.getItem('idToken') ||
      localStorage.getItem('accessToken') ||
      localStorage.getItem('token')
    );
  };

  useEffect(() => {
    const email = localStorage.getItem('email');
    const userType = localStorage.getItem('userType');
    const sessionId = localStorage.getItem('sessionId');
    const userId = localStorage.getItem('userId');

    if (!userId || userType !== 'customer') {
      window.location.href = '/';
    } else {
      setCurrentUser({ userId, email, userType, sessionId });
      fetchAvailableBikes();
    }
  }, [selectedDate]);

  const fetchAvailableBikes = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${API_BASE}/bikes?date=${selectedDate}`);
      setBikes(res.data);
    } catch (err) {
      console.error('Error fetching bikes:', err);
      toast.error('Failed to load bikes.');
    } finally {
      setLoading(false);
    }
  };

  const handleBookBike = async (bikeId) => {
    try {
      const token = getAuthToken();
      if (!token) {
        toast.error('Authentication token missing.');
        localStorage.clear();
        window.location.href = '/login';
        return;
      }

      await axios.post(
        `${API_BASE}/bookings`,
        { bike_id: bikeId, date: selectedDate },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      toast.success('Booking successful!');
      fetchAvailableBikes();
    } catch (err) {
      const message =
        err.response?.data?.error || err.response?.data?.message || 'Booking failed.';
      toast.error(message);
    }
  };

  const tabs = [
    { key: 'booking', label: 'Book Bike', icon: '' },
    { key: 'myBookings', label: 'My Bookings', icon: '' },
    { key: 'messages', label: 'Messages', icon: '' },
    { key: 'feedback', label: 'Feedback', icon: '' },
    { key: 'profile', label: 'Profile', icon: '' },
  ];

  if (!currentUser) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-2xl shadow-2xl">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600 text-center">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      {/* Modern Header */}
      <header className="bg-white/80 backdrop-blur-lg shadow-lg border-b border-white/20 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl flex items-center justify-center">
                <span className="text-white font-bold text-lg"></span>
              </div>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  DALScooter
                </h1>
                <p className="text-sm text-gray-500">Customer Dashboard</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="hidden md:flex items-center space-x-2 bg-blue-50 px-4 py-2 rounded-full">
                <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                  <span className="text-white text-sm font-semibold">
                    {currentUser.email.charAt(0).toUpperCase()}
                  </span>
                </div>
                <span className="text-blue-700 font-medium">{currentUser.email}</span>
              </div>
              
              <button
                onClick={() => {
                  localStorage.clear();
                  window.location.href = '/';
                }}
                className="bg-red-50 hover:bg-red-100 text-red-600 px-4 py-2 rounded-full font-medium transition-all duration-200 hover:scale-105"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Enhanced Tab Navigation */}
      <nav className="bg-white/60 backdrop-blur-sm border-b border-white/20 sticky top-[88px] z-40">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex space-x-2 overflow-x-auto scrollbar-hide">
            {tabs.map((tab) => (
              <button
                key={tab.key}
                onClick={() => {
                  setActiveTab(tab.key);
                  // Reset chat when switching away from messages tab
                  if (tab.key !== 'messages') {
                    setChatBookingId(null);
                  }
                }}
                className={`flex items-center space-x-2 px-6 py-3 rounded-xl font-semibold transition-all duration-200 whitespace-nowrap ${
                  activeTab === tab.key
                    ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg transform scale-105'
                    : 'bg-white/70 text-gray-700 hover:bg-white hover:shadow-md hover:scale-102'
                }`}
              >
                <span className="text-lg">{tab.icon}</span>
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content with improved spacing */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {activeTab === 'booking' && (
          <div className="space-y-8">
            {/* Date Selector */}
            <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl p-6 border border-white/20">
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <div className="flex items-center space-x-3">
                  <span className="text-2xl"></span>
                  <label className="text-lg font-semibold text-gray-700">Select Date:</label>
                </div>
                <input
                  type="date"
                  value={selectedDate}
                  min={new Date().toISOString().split('T')[0]}
                  onChange={(e) => setSelectedDate(e.target.value)}
                  className="px-4 py-3 border-2 border-blue-200 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all duration-200 bg-white/80"
                />
              </div>
            </div>

            {/* Bikes Grid */}
            {loading ? (
              <div className="flex flex-col items-center justify-center py-16 space-y-4">
                <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600"></div>
                <p className="text-xl text-gray-600">Finding available bikes...</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                {bikes.length === 0 ? (
                  <div className="col-span-full text-center py-16">
                    <div className="text-6xl mb-4">🚲</div>
                    <p className="text-xl text-gray-500 mb-2">No bikes available</p>
                    <p className="text-gray-400">Try selecting a different date</p>
                  </div>
                ) : (
                  bikes.map((bike) => (
                    <div
                      key={bike.bike_id}
                      className="group bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 p-6 space-y-4 hover:shadow-2xl hover:scale-105 transition-all duration-300"
                    >
                      {/* Bike Header */}
                      <div className="flex justify-between items-start">
                        <div className="space-y-1">
                          <h4 className="text-xl font-bold text-gray-800">{bike.type}</h4>
                          <p className="text-sm text-gray-500 font-mono">
                            ID: {bike.bike_id.slice(0, 8)}...
                          </p>
                        </div>
                        <div className="text-right space-y-1">
                          <div className="bg-gradient-to-r from-green-500 to-emerald-500 text-white px-3 py-1 rounded-full">
                            <span className="font-bold">${bike.dailyRate}</span>
                            <span className="text-sm">/day</span>
                          </div>
                          <p className="text-xs text-gray-500">
                            <span className="font-semibold text-blue-600">{bike.availableCount}</span>
                            /{bike.totalCount} available
                          </p>
                        </div>
                      </div>

                      {/* Features */}
                      <div className="space-y-2">
                        <p className="text-sm font-semibold text-gray-700 flex items-center space-x-2">
                          <span></span>
                          <span>Features:</span>
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {(typeof bike.features === 'string'
                            ? bike.features.split(',')
                            : Object.values(bike.features || {})
                          ).map((feature, idx) => (
                            <span
                              key={idx}
                              className="bg-gradient-to-r from-blue-100 to-purple-100 text-blue-800 text-xs px-3 py-1 rounded-full font-medium border border-blue-200"
                            >
                              {feature.trim()}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Availability Bar */}
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-gradient-to-r from-green-400 to-emerald-500 h-2 rounded-full transition-all duration-300"
                          style={{
                            width: `${(bike.availableCount / bike.totalCount) * 100}%`,
                          }}
                        ></div>
                      </div>

                      {/* Book Button */}
                      <button
                        onClick={() => handleBookBike(bike.bike_id)}
                        disabled={!bike.available || bike.availableCount <= 0}
                        className={`w-full font-semibold py-3 px-6 rounded-xl transition-all duration-200 ${
                          bike.available && bike.availableCount > 0
                            ? 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-lg hover:shadow-xl transform hover:scale-105'
                            : 'bg-gray-200 text-gray-500 cursor-not-allowed'
                        }`}
                      >
                        {bike.available && bike.availableCount > 0 ? (
                          <span className="flex items-center justify-center space-x-2">
                            <span></span>
                            <span>Book This Bike</span>
                          </span>
                        ) : (
                          <span className="flex items-center justify-center space-x-2">
                            <span></span>
                            <span>Unavailable</span>
                          </span>
                        )}
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'myBookings' && (
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl p-6 border border-white/20">
            <MyBookings token={getAuthToken()} />
          </div>
        )}

        {/* UPDATED MESSAGES SECTION - Fixed Layout */}
        {activeTab === 'messages' && (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 h-[600px]">
            {/* Conversations List - Fixed Height Container */}
            <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 flex flex-col overflow-hidden">
              <div className="flex items-center space-x-3 p-6 border-b border-gray-200 flex-shrink-0">
                <span className="text-2xl"></span>
                <div>
                  <h2 className="text-xl font-bold text-gray-800">Conversations</h2>
                  <p className="text-sm text-gray-600">Select a booking to chat</p>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto p-6">
                <CustomerConversationList onOpenChat={setChatBookingId} />
              </div>
            </div>

            {/* Chat Area - Fixed Height Container */}
            <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 flex flex-col overflow-hidden">
              {chatBookingId ? (
                <>
                  <div className="flex items-center justify-between p-6 border-b border-gray-200 flex-shrink-0">
                    <div className="flex items-center space-x-3">
                      <span className="text-2xl"></span>
                      <div>
                        <h2 className="text-xl font-bold text-gray-800">Active Chat</h2>
                        <p className="text-sm text-gray-600">Support conversation</p>
                      </div>
                    </div>
                    <button
                      onClick={() => setChatBookingId(null)}
                      className="bg-gray-100 hover:bg-gray-200 text-gray-600 p-2 rounded-full transition-all duration-200 hover:scale-110"
                    >
                      ✕
                    </button>
                  </div>
                  <div className="flex-1 min-h-0">
                    <CustomerChatModal
                      bookingId={chatBookingId}
                      onClose={() => setChatBookingId(null)}
                      embedded={true}
                    />
                  </div>
                </>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
                  <div className="w-16 h-16 bg-gradient-to-r from-gray-200 to-gray-300 rounded-full flex items-center justify-center mb-6">
                    <span className="text-2xl text-gray-500"></span>
                  </div>
                  <h3 className="text-xl font-bold text-gray-800 mb-2">Select a Conversation</h3>
                  <p className="text-gray-600">Choose a booking from the conversations list to start chatting</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'feedback' && (
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl p-8 border border-white/20">
            <div className="flex items-center space-x-3 mb-6">
              <span className="text-3xl"></span>
              <h2 className="text-2xl font-bold text-gray-800">Submit Feedback</h2>
            </div>
            <SubmitFeedbackFromBookings />
          </div>
        )}

        {activeTab === 'profile' && (
          <div className="bg-white/80 backdrop-blur-sm rounded-2xl shadow-xl p-8 border border-white/20">
            <div className="flex items-center space-x-3 mb-6">
              <span className="text-3xl"></span>
              <h2 className="text-2xl font-bold text-gray-800">Profile Settings</h2>
            </div>
            <CustomerProfile />
          </div>
        )}
      </main>
    </div>
  );
}
