import React, { useState } from 'react';
import OverviewSection from '../components/Franchise/OverviewSection';
import BikeManagementSection from '../components/Franchise/BikeManagementSection';
import BookingSection from '../components/Franchise/BookingSection';
import SupportSection from '../components/Franchise/SupportSection';

export default function FranchiseDashboard() {
  const [activeTab, setActiveTab] = useState('overview');

  const [bikes, setBikes] = useState([
    { id: 1, type: 'eBike', model: 'EB-001', accessCode: 'A1B2C3', status: 'Available', rate: 15, battery: 85, features: ['Height Adjustment', 'GPS Tracking'] },
    { id: 2, type: 'Gyroscooter', model: 'GS-002', accessCode: 'D4E5F6', status: 'Rented', rate: 20, battery: 60, features: ['Self-Balancing', 'LED Display'] },
    { id: 3, type: 'Segway', model: 'SW-003', accessCode: 'G7H8I9', status: 'Available', rate: 25, battery: 90, features: ['Remote Control', 'Anti-theft'] }
  ]);

  const [bookings, setBookings] = useState([
    { id: 'BK001', customer: 'John Doe', bikeId: 2, startTime: '09:00', endTime: '12:00', date: '2025-01-29', status: 'Active' },
    { id: 'BK002', customer: 'Jane Smith', bikeId: 1, startTime: '14:00', endTime: '16:00', date: '2025-01-29', status: 'Completed' }
  ]);

  const [tickets, setTickets] = useState([
    { id: 'T001', customer: 'John Doe', issue: 'Bike not starting', priority: 'High', status: 'Open', timestamp: '2025-01-29 10:30' },
    { id: 'T002', customer: 'Jane Smith', issue: 'Battery drain issue', priority: 'Medium', status: 'In Progress', timestamp: '2025-01-29 11:15' }
  ]);

  const [showAddBike, setShowAddBike] = useState(false);
  const [showChat, setShowChat] = useState(false);
  const [selectedTicket, setSelectedTicket] = useState(null);

  const [newBike, setNewBike] = useState({
    type: 'eBike',
    model: '',
    accessCode: '',
    rate: '',
    features: ''
  });

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

  const getBikeByBookingRef = (bookingRef) => {
    const booking = bookings.find(b => b.id === bookingRef);
    if (booking) {
      const bike = bikes.find(b => b.id === booking.bikeId);
      return { booking, bike };
    }
    return null;
  };

  const tabs = [
    { id: 'overview', name: 'Overview', icon: '📊' },
    { id: 'bikes', name: 'Bike Management', icon: '🚲' },
    { id: 'bookings', name: 'Bookings', icon: '📅' },
    { id: 'support', name: 'Support', icon: '💬' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
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
            <div className="flex items-center space-x-4">
              <button className="text-blue-600 hover:text-blue-800 transition-colors">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-5 5v-5zM21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </button>
              <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
                <span className="text-white font-semibold">F</span>
              </div>
            </div>
          </div>
        </div>
      </div>

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

        <div className="mb-16">
          {activeTab === 'overview' && (
            <OverviewSection bikes={bikes} bookings={bookings} tickets={tickets} />
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
          {activeTab === 'bookings' && (
            <BookingSection
              bookings={bookings}
              bikes={bikes}
              getBikeByBookingRef={getBikeByBookingRef}
            />
          )}
          {activeTab === 'support' && (
            <SupportSection
              tickets={tickets}
              selectedTicket={selectedTicket}
              setSelectedTicket={setSelectedTicket}
              showChat={showChat}
              setShowChat={setShowChat}
            />
          )}
        </div>
      </div>
    </div>
  );
}
