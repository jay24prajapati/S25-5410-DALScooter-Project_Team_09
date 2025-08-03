import React, { useEffect, useState } from 'react';
import axios from 'axios';
import CustomerProfile from '../components/Customer/CustomerProfile';
import MyBookings from '../components/Customer/MyBookings';
import BookingMessages from '../components/Customer/BookingMessages';
import SubmitFeedback from '../components/Customer/SubmitFeedback';
import { toast } from 'react-toastify';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerDashboard() {
  const [currentUser, setCurrentUser] = useState(null);
  const [bikes, setBikes] = useState([]);
  const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('booking');
  const [selectedBookingId, setSelectedBookingId] = useState('');
  const [selectedBikeId, setSelectedBikeId] = useState('');

  const token = localStorage.getItem('accessToken');

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
      const res = await axios.get(`${API_BASE}/bikes?date=${selectedDate}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
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
      await axios.post(
        `${API_BASE}/bookings`,
        { bike_id: bikeId, date: selectedDate },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success('Booking successful!');
      fetchAvailableBikes();
    } catch (err) {
      console.error('Booking failed:', err);
      toast.error('Booking failed.');
    }
  };

  if (!currentUser) return null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-blue-100">
      {/* Top Bar */}
      <header className="bg-white shadow p-5 flex justify-between items-center">
        <h1 className="text-2xl font-bold text-blue-800">DALScooter | Customer Dashboard</h1>
        <div className="text-blue-600">Welcome, {currentUser.email}</div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-blue-100 px-4 py-3 flex gap-4 justify-center">
        {[
          { key: 'booking', label: 'Book Bike' },
          { key: 'myBookings', label: 'My Bookings' },
          { key: 'messages', label: 'Messages' },
          { key: 'feedback', label: 'Submit Feedback' },
          { key: 'profile', label: 'Profile' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 font-semibold rounded ${
              activeTab === tab.key
                ? 'bg-blue-600 text-white'
                : 'bg-white text-blue-800 border border-blue-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Main Content */}
      <main className="p-6">
        {activeTab === 'booking' && (
          <>
            <div className="p-4 flex items-center justify-center gap-4">
              <label className="font-semibold text-blue-700">Select Date:</label>
              <input
                type="date"
                value={selectedDate}
                onChange={(e) => setSelectedDate(e.target.value)}
                className="p-2 border border-blue-300 rounded"
              />
            </div>

            {loading ? (
              <p className="text-center text-blue-600">Loading available bikes...</p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {bikes.length === 0 ? (
                  <p className="text-center col-span-full text-gray-500">
                    No bikes available for selected date.
                  </p>
                ) : (
                  bikes.map((bike) => (
                    <div
                      key={bike.bike_id}
                      className="bg-white rounded-xl shadow border border-blue-100 p-6 space-y-3"
                    >
                      <div className="flex justify-between items-center">
                        <div>
                          <h4 className="text-lg font-bold text-gray-800">
                            Scooter ID: {bike.bike_id.slice(0, 6)}...
                          </h4>
                          <p className="text-blue-600 font-semibold">{bike.type}</p>
                        </div>
                        <span className="font-semibold text-green-600">
                          ${bike.dailyRate}/day
                        </span>
                      </div>
                      <div>
                        <p className="text-sm text-gray-600 mb-1">Features:</p>
                        <div className="flex flex-wrap gap-2">
                          {String(bike.features || '')
                            .split(',')
                            .map((f, idx) => (
                              <span
                                key={idx}
                                className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full"
                              >
                                {f.trim()}
                              </span>
                            ))}
                        </div>
                      </div>
                      <button
                        onClick={() => handleBookBike(bike.bike_id)}
                        className="w-full mt-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg transition-all"
                      >
                        Book This Bike
                      </button>
                    </div>
                  ))
                )}
              </div>
            )}
          </>
        )}

        {activeTab === 'myBookings' && <MyBookings token={token} />}

        {activeTab === 'messages' && (
          <div className="max-w-xl mx-auto">
            <input
              type="text"
              placeholder="Enter booking ID"
              value={selectedBookingId}
              onChange={(e) => setSelectedBookingId(e.target.value)}
              className="mb-4 p-2 w-full border rounded"
            />
            {selectedBookingId && <BookingMessages bookingId={selectedBookingId} />}
          </div>
        )}

        {activeTab === 'feedback' && (
          <div className="max-w-xl mx-auto">
            <input
              type="text"
              placeholder="Booking ID"
              value={selectedBookingId}
              onChange={(e) => setSelectedBookingId(e.target.value)}
              className="mb-2 p-2 w-full border rounded"
            />
            <input
              type="text"
              placeholder="Bike ID"
              value={selectedBikeId}
              onChange={(e) => setSelectedBikeId(e.target.value)}
              className="mb-4 p-2 w-full border rounded"
            />
            {selectedBookingId && selectedBikeId && (
              <SubmitFeedback bookingId={selectedBookingId} bikeId={selectedBikeId} />
            )}
          </div>
        )}

        {activeTab === 'profile' && <CustomerProfile />}
      </main>
    </div>
  );
}
