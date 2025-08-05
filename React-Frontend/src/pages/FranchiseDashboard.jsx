import React, { useState, useEffect } from 'react';
import OverviewSection from '../components/Franchise/OverviewSection';
import BikeManagementSection from '../components/Franchise/BikeManagementSection';
import BookingSection from '../components/Franchise/BookingSection';
import SupportSection from '../components/Franchise/SupportSection';
import CustomerList from '../components/Franchise/CustomerList';
import ConversationList from '../components/Franchise/ConversationList';
import ChatModal from '../components/Franchise/ChatModal';

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

  const [showChat, setShowChat] = useState(false);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [selectedBookingId, setSelectedBookingId] = useState(null);

  useEffect(() => {
    // Auto-close chat when tab changes
    setShowChat(false);
    setSelectedBookingId(null);
    setSelectedTicket(null);
  }, [activeTab]);

  const handleAddBike = (e) => {
    e.preventDefault();
    const bike = {
      id: bikes.length + 1,
      type: newBike.type,
      model: newBike.model,
      accessCode: newBike.accessCode,
      status: 'Available',
      rate: parseFloat(newBike.rate),
      battery: 100,
      features: newBike.features.split(',').map(f => f.trim())
    };
    setBikes([...bikes, bike]);
    setShowAddBike(false);
    setNewBike({ type: 'eBike', model: '', accessCode: '', rate: '', features: '' });
  };

  const updateBikeRate = (bikeId, newRate) => {
    setBikes(bikes.map(bike =>
      bike.id === bikeId ? { ...bike, rate: newRate } : bike
    ));
  };

  const tabs = [
  { id: 'overview', name: 'Overview', icon: '📊' },
  { id: 'bikes', name: 'Bike Management', icon: '🚲' },
  { id: 'bookings', name: 'Bookings', icon: '📅' },
  { id: 'support', name: 'Customers', icon: '👥' }, // updated icon and label
  { id: 'messages', name: 'Messages', icon: '💬' }   // renamed cleanly
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
            <div className="flex items-center">
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
            <OverviewSection bookings={[]} tickets={tickets} />
          )}

          {activeTab === 'bikes' && (
            <BikeManagementSection
              bikes={bikes}
              setBikes={setBikes}
              showAddBike={showAddBike}
              setShowAddBike={setShowAddBike}
              newBike={newBike}
              setNewBike={setNewBike}
              handleAddBike={handleAddBike}
              updateBikeRate={updateBikeRate}
            />
          )}

          {activeTab === 'bookings' && <BookingSection />}

          {activeTab === 'support' && (
  <SupportSection /> 
)}



          {activeTab === 'messages' && (
  <ConversationList onOpenChat={(bookingId) => setSelectedBookingId(bookingId)} />
)}


          {/* Chat Modal (global) */}
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
