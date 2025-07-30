import React, { useState } from 'react';

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

  const renderOverview = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gradient-to-r from-blue-500 to-blue-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Total Bikes</p>
              <p className="text-3xl font-bold">{bikes.length}</p>
            </div>
            <svg className="w-12 h-12 text-blue-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
        </div>
        <div className="bg-gradient-to-r from-green-500 to-green-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-100 text-sm">Available</p>
              <p className="text-3xl font-bold">{bikes.filter(b => b.status === 'Available').length}</p>
            </div>
            <svg className="w-12 h-12 text-green-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>
        <div className="bg-gradient-to-r from-orange-500 to-orange-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-orange-100 text-sm">Active Bookings</p>
              <p className="text-3xl font-bold">{bookings.filter(b => b.status === 'Active').length}</p>
            </div>
            <svg className="w-12 h-12 text-orange-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>
        <div className="bg-gradient-to-r from-red-500 to-red-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-100 text-sm">Open Tickets</p>
              <p className="text-3xl font-bold">{tickets.filter(t => t.status === 'Open').length}</p>
            </div>
            <svg className="w-12 h-12 text-red-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.728-.833-2.498 0L4.316 15.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl shadow-lg p-6 border border-blue-100">
        <h3 className="text-xl font-bold text-blue-800 mb-4">Recent Activity</h3>
        <div className="space-y-3">
          <div className="flex items-center p-3 bg-blue-50 rounded-lg">
            <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
            <span className="text-blue-700">New booking BK003 received for Segway SW-003</span>
            <span className="ml-auto text-blue-500 text-sm">5 min ago</span>
          </div>
          <div className="flex items-center p-3 bg-green-50 rounded-lg">
            <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
            <span className="text-green-700">eBike EB-001 returned successfully</span>
            <span className="ml-auto text-green-500 text-sm">15 min ago</span>
          </div>
          <div className="flex items-center p-3 bg-orange-50 rounded-lg">
            <div className="w-2 h-2 bg-orange-500 rounded-full mr-3"></div>
            <span className="text-orange-700">New support ticket T003 created</span>
            <span className="ml-auto text-orange-500 text-sm">30 min ago</span>
          </div>
        </div>
      </div>
    </div>
  );

  const renderBikeManagement = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h3 className="text-2xl font-bold text-blue-800">Bike Fleet Management</h3>
        <button
          onClick={() => setShowAddBike(true)}
          className="bg-gradient-to-r from-blue-500 to-blue-600 text-white px-6 py-3 rounded-xl font-semibold hover:from-blue-600 hover:to-blue-700 transition-all shadow-lg"
        >
          Add New Bike
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {bikes.map(bike => (
          <div key={bike.id} className="bg-white rounded-xl shadow-lg border border-blue-100 overflow-hidden">
            <div className={`h-2 ${bike.type === 'eBike' ? 'bg-green-500' : bike.type === 'Gyroscooter' ? 'bg-blue-500' : 'bg-purple-500'}`}></div>
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h4 className="text-lg font-bold text-gray-800">{bike.model}</h4>
                  <p className="text-blue-600 font-semibold">{bike.type}</p>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                  bike.status === 'Available' ? 'bg-green-100 text-green-800' : 'bg-orange-100 text-orange-800'
                }`}>
                  {bike.status}
                </span>
              </div>

              <div className="space-y-3 mb-4">
                <div className="flex justify-between">
                  <span className="text-gray-600">Access Code:</span>
                  <span className="font-mono bg-gray-100 px-2 py-1 rounded text-sm">{bike.accessCode}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Battery:</span>
                  <div className="flex items-center">
                    <div className="w-16 h-2 bg-gray-200 rounded-full mr-2">
                      <div className={`h-2 rounded-full ${bike.battery > 50 ? 'bg-green-500' : 'bg-orange-500'}`} 
                           style={{width: `${bike.battery}%`}}></div>
                    </div>
                    <span className="text-sm">{bike.battery}%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600">Hourly Rate:</span>
                  <div className="flex items-center">
                    <span className="mr-2">${bike.rate}</span>
                    <button
                      onClick={() => {
                        const newRate = prompt('Enter new hourly rate:', bike.rate);
                        if (newRate) updateBikeRate(bike.id, parseFloat(newRate));
                      }}
                      className="text-blue-500 hover:text-blue-700 text-sm"
                    >
                      Edit
                    </button>
                  </div>
                </div>
              </div>

              <div className="mb-4">
                <p className="text-gray-600 text-sm mb-2">Features:</p>
                <div className="flex flex-wrap gap-1">
                  {bike.features.map((feature, idx) => (
                    <span key={idx} className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full">
                      {feature}
                    </span>
                  ))}
                </div>
              </div>

              <button className="w-full bg-blue-50 text-blue-600 py-2 rounded-lg hover:bg-blue-100 transition-colors font-semibold">
                Manage Bike
              </button>
            </div>
          </div>
        ))}
      </div>

      {showAddBike && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-8 w-full max-w-md mx-4">
            <h3 className="text-xl font-bold text-blue-800 mb-6">Add New Bike</h3>
            <form onSubmit={handleAddBike} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Bike Type</label>
                <select
                  value={newBike.type}
                  onChange={(e) => setNewBike({...newBike, type: e.target.value})}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                >
                  <option value="eBike">eBike</option>
                  <option value="Gyroscooter">Gyroscooter</option>
                  <option value="Segway">Segway</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Model</label>
                <input
                  type="text"
                  value={newBike.model}
                  onChange={(e) => setNewBike({...newBike, model: e.target.value})}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Access Code</label>
                <input
                  type="text"
                  value={newBike.accessCode}
                  onChange={(e) => setNewBike({...newBike, accessCode: e.target.value})}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Hourly Rate ($)</label>
                <input
                  type="number"
                  value={newBike.rate}
                  onChange={(e) => setNewBike({...newBike, rate: e.target.value})}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Features (comma-separated)</label>
                <input
                  type="text"
                  value={newBike.features}
                  onChange={(e) => setNewBike({...newBike, features: e.target.value})}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  placeholder="GPS Tracking, Height Adjustment"
                />
              </div>
              <div className="flex space-x-4 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-gradient-to-r from-blue-500 to-blue-600 text-white py-3 rounded-lg font-semibold hover:from-blue-600 hover:to-blue-700 transition-all"
                >
                  Add Bike
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddBike(false)}
                  className="flex-1 bg-gray-200 text-gray-700 py-3 rounded-lg font-semibold hover:bg-gray-300 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );

  const renderBookings = () => (
    <div className="space-y-6">
      <h3 className="text-2xl font-bold text-blue-800">Booking Management</h3>
      
      <div className="bg-white rounded-xl shadow-lg border border-blue-100">
        <div className="p-6 border-b border-blue-100">
          <h4 className="text-lg font-semibold text-blue-700">Booking Reference Lookup</h4>
          <div className="mt-4 flex space-x-4">
            <input
              type="text"
              placeholder="Enter booking reference (e.g., BK001)"
              className="flex-1 p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  const result = getBikeByBookingRef(e.target.value);
                  if (result) {
                    alert(`Bike: ${result.bike.model}\nDuration: ${result.booking.startTime} - ${result.booking.endTime}\nAccess Code: ${result.bike.accessCode}`);
                  } else {
                    alert('Booking reference not found');
                  }
                }
              }}
            />
            <button className="bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 transition-colors">
              Lookup
            </button>
          </div>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-blue-50">
              <tr>
                <th className="px-6 py-4 text-left text-blue-700 font-semibold">Booking ID</th>
                <th className="px-6 py-4 text-left text-blue-700 font-semibold">Customer</th>
                <th className="px-6 py-4 text-left text-blue-700 font-semibold">Bike</th>
                <th className="px-6 py-4 text-left text-blue-700 font-semibold">Date</th>
                <th className="px-6 py-4 text-left text-blue-700 font-semibold">Time</th>
                <th className="px-6 py-4 text-left text-blue-700 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {bookings.map(booking => {
                const bike = bikes.find(b => b.id === booking.bikeId);
                return (
                  <tr key={booking.id} className="border-b border-blue-100 hover:bg-blue-50">
                    <td className="px-6 py-4 font-mono text-blue-600">{booking.id}</td>
                    <td className="px-6 py-4">{booking.customer}</td>
                    <td className="px-6 py-4">{bike?.model} ({bike?.type})</td>
                    <td className="px-6 py-4">{booking.date}</td>
                    <td className="px-6 py-4">{booking.startTime} - {booking.endTime}</td>
                    <td className="px-6 py-4">
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        booking.status === 'Active' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
                      }`}>
                        {booking.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderSupport = () => (
    <div className="space-y-6">
      <h3 className="text-2xl font-bold text-blue-800">Customer Support</h3>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl shadow-lg border border-blue-100">
          <div className="p-6 border-b border-blue-100">
            <h4 className="text-lg font-semibold text-blue-700">Support Tickets</h4>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {tickets.map(ticket => (
              <div key={ticket.id} className="p-4 border-b border-blue-50 hover:bg-blue-50 cursor-pointer"
                   onClick={() => {setSelectedTicket(ticket); setShowChat(true);}}>
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <p className="font-semibold text-blue-800">#{ticket.id}</p>
                    <p className="text-sm text-gray-600">{ticket.customer}</p>
                  </div>
                  <div className="text-right">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                      ticket.priority === 'High' ? 'bg-red-100 text-red-800' : 
                      ticket.priority === 'Medium' ? 'bg-orange-100 text-orange-800' : 'bg-green-100 text-green-800'
                    }`}>
                      {ticket.priority}
                    </span>
                    <p className="text-xs text-gray-500 mt-1">{ticket.timestamp}</p>
                  </div>
                </div>
                <p className="text-gray-700 text-sm mb-2">{ticket.issue}</p>
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                  ticket.status === 'Open' ? 'bg-red-100 text-red-800' : 
                  ticket.status === 'In Progress' ? 'bg-orange-100 text-orange-800' : 'bg-green-100 text-green-800'
                }`}>
                  {ticket.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-lg border border-blue-100">
          <div className="p-6 border-b border-blue-100">
            <h4 className="text-lg font-semibold text-blue-700">Virtual Assistant</h4>
          </div>
          <div className="p-6">
            <div className="bg-blue-50 rounded-lg p-4 mb-4">
              <p className="text-blue-800 font-semibold mb-2">🤖 DAL Assistant</p>
              <p className="text-blue-700 text-sm">Hello! I can help you with:</p>
              <ul className="text-blue-600 text-sm mt-2 space-y-1">
                <li>• Site navigation</li>
                <li>• Booking reference lookups</li>
                <li>• Bike information</li>
                <li>• Customer communication</li>
              </ul>
            </div>
            <div className="flex space-x-2">
              <input
                type="text"
                placeholder="Ask me anything..."
                className="flex-1 p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <button className="bg-blue-500 text-white px-4 py-3 rounded-lg hover:bg-blue-600 transition-colors">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </div>

      {showChat && selectedTicket && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl w-full max-w-2xl mx-4 h-3/4 flex flex-col">
            <div className="p-6 border-b border-blue-100">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-xl font-bold text-blue-800">Support Chat - #{selectedTicket.id}</h3>
                  <p className="text-blue-600">{selectedTicket.customer}</p>
                </div>
                <button
                  onClick={() => setShowChat(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            
            <div className="flex-1 p-6 overflow-y-auto">
              <div className="space-y-4">
                <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg">
                  <p className="text-red-800 font-semibold">Issue: {selectedTicket.issue}</p>
                  <p className="text-red-600 text-sm mt-1">{selectedTicket.timestamp}</p>
                </div>
                <div className="bg-blue-50 border-l-4 border-blue-400 p-4 rounded-r-lg ml-8">
                  <p className="text-blue-800">Thank you for contacting us. We're looking into your issue.</p>
                  <p className="text-blue-600 text-sm mt-1">Franchise Support</p>
                </div>
              </div>
            </div>
            
            <div className="p-6 border-t border-blue-100">
              <div className="flex space-x-4">
                <input
                  type="text"
                  placeholder="Type your response..."
                  className="flex-1 p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                />
                <button className="bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 transition-colors font-semibold">
                  Send
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const tabs = [
    { id: 'overview', name: 'Overview', icon: '📊' },
    { id: 'bikes', name: 'Bike Management', icon: '🚲' },
    { id: 'bookings', name: 'Bookings', icon: '📅' },
    { id: 'support', name: 'Support', icon: '💬' }
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
              {activeTab === 'overview' && renderOverview()}
              {activeTab === 'bikes' && renderBikeManagement()}
              {activeTab === 'bookings' && renderBookings()}
              {activeTab === 'support' && renderSupport()}
            </div>
          </div>
        </div>
      );
    }

    