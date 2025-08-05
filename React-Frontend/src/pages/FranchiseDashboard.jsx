import React, { useState, useEffect } from 'react';
import axios from 'axios';
import OverviewSection from '../components/Franchise/OverviewSection';
import BikeManagementSection from '../components/Franchise/BikeManagementSection';
import BookingSection from '../components/Franchise/BookingSection';
import SupportSection from '../components/Franchise/SupportSection';
import ConversationList from '../components/Franchise/ConversationList';
import ChatModal from '../components/Franchise/ChatModal';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function FranchiseDashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [bikes, setBikes] = useState([]);
  const [tickets, setTickets] = useState([]);

  const [showAddBike, setShowAddBike] = useState(false);
  const [newBike, setNewBike] = useState({
    type: 'eBike',
    model: '',
    accessCode: '',
    rate: '',
    features: ''
  });

  const [selectedBookingId, setSelectedBookingId] = useState(null);

  // Auto-close chat modal on tab switch
  useEffect(() => {
    setSelectedBookingId(null);
  }, [activeTab]);

  // Fetch bikes from backend
  useEffect(() => {
    const fetchBikes = async () => {
      try {
        const token = localStorage.getItem('idToken');
        const today = new Date().toISOString().split('T')[0];
        const res = await axios.get(`${API_BASE}/bikes?date=${today}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setBikes(res.data);
      } catch (err) {
        console.error('Failed to fetch bikes:', err);
      }
    };
    fetchBikes();
  }, []);

  const tabs = [
    { id: 'overview', name: 'Overview', icon: '' },
    { id: 'bikes', name: 'Bike Management', icon: '' },
    { id: 'bookings', name: 'Bookings', icon: '' },
    { id: 'support', name: 'Customers', icon: '' },
    { id: 'messages', name: 'Messages', icon: '' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <div className="bg-white shadow-lg border-b border-blue-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center mr-4">
                <span className="text-white font-bold text-xl">DS</span>
              </div>
              <div>
                <h1 className="text-2xl font-bold text-blue-800">DALScooter Franchise</h1>
                <p className="text-blue-600">Franchise Dashboard</p>
              </div>
            </div>
            <div>
              <button
                onClick={() => {
                  localStorage.clear();
                  window.location.href = '/login';
                }}
                className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-semibold transition-all"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-8">
        <div className="flex space-x-4 mb-8">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center px-6 py-3 rounded-xl font-semibold transition-all shadow-lg ${
                activeTab === tab.id
                  ? 'bg-gradient-to-r from-blue-500 to-blue-600 text-white'
                  : 'bg-white text-blue-700 border border-blue-200 hover:bg-blue-50'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.name}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="mb-16">
          {activeTab === 'overview' && (
            <OverviewSection bookings={[]} tickets={tickets} bikes={bikes} />
          )}

          {activeTab === 'bikes' && (
            <BikeManagementSection
              bikes={bikes}
              setBikes={setBikes}
              showAddBike={showAddBike}
              setShowAddBike={setShowAddBike}
              newBike={newBike}
              setNewBike={setNewBike}
            />
          )}

          {activeTab === 'bookings' && <BookingSection />}

          {activeTab === 'support' && <SupportSection />}

          {activeTab === 'messages' && (
            <ConversationList onOpenChat={(bookingId) => setSelectedBookingId(bookingId)} />
          )}

          {/* Chat Modal */}
          {selectedBookingId && (
            <ChatModal
              bookingId={selectedBookingId}
              onClose={() => setSelectedBookingId(null)}
            />
          )}
        </div>
      </div>
    </div>
  );
}
