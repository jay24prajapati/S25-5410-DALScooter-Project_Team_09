import React, { useEffect } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function BikeManagementSection({
  bikes,
  setBikes,
  showAddBike,
  setShowAddBike,
  newBike,
  setNewBike
}) {
  const token = localStorage.getItem('accessToken');

  // 🔁 Load all bikes initially
  useEffect(() => {
    fetchBikes();
  }, []);

  const fetchBikes = async () => {
    try {
      const res = await axios.get(`${API_BASE}/bikes`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      setBikes(res.data);
    } catch (err) {
      console.error('Failed to load bikes:', err);
    }
  };

  const handleAddBike = async (e) => {
    e.preventDefault();
    const count = parseInt(newBike.count);
    if (isNaN(count) || count <= 0) {
      alert('Please enter a valid count');
      return;
    }

    try {
      const res = await axios.post(
        `${API_BASE}/bikes`,
        {
          type: newBike.type,
          dailyRate: parseFloat(newBike.dailyRate),
          features: newBike.features, // plain string
          count
        },
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      console.log('Bike added:', res.data);
      await fetchBikes();
      setShowAddBike(false);
      setNewBike({ type: 'eBike', dailyRate: '', features: '', count: '' });
    } catch (err) {
      console.error('Failed to add bike:', err.message);
      alert(`Add failed: ${err.message}`);
    }
  };

  return (
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
        {bikes.map((bike) => (
          <div key={bike.id} className="bg-white rounded-xl shadow-lg border border-blue-100 overflow-hidden">
            <div
              className={`h-2 ${
                bike.type === 'eBike'
                  ? 'bg-green-500'
                  : bike.type === 'Gyroscooter'
                  ? 'bg-blue-500'
                  : 'bg-purple-500'
              }`}
            ></div>
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h4 className="text-lg font-bold text-gray-800">{bike.model}</h4>
                  <p className="text-blue-600 font-semibold">{bike.type}</p>
                </div>
                <span
                  className={`px-3 py-1 rounded-full text-xs font-semibold ${
                    bike.status === 'Available'
                      ? 'bg-green-100 text-green-800'
                      : 'bg-orange-100 text-orange-800'
                  }`}
                >
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
                      <div
                        className={`h-2 rounded-full ${
                          bike.battery > 50 ? 'bg-green-500' : 'bg-orange-500'
                        }`}
                        style={{ width: `${bike.battery}%` }}
                      ></div>
                    </div>
                    <span className="text-sm">{bike.battery}%</span>
                  </div>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-gray-600">Daily Rate:</span>
                  <div className="flex items-center">
                    <span className="mr-2">${bike.rate}</span>
                  </div>
                </div>
              </div>

              <div className="mb-4">
                <p className="text-gray-600 text-sm mb-2">Features:</p>
                <div className="flex flex-wrap gap-1">
                  {bike.features?.split(',').map((f, idx) => (
                    <span
                      key={idx}
                      className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full"
                    >
                      {f.trim()}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {showAddBike && (
        <div className="fixed inset-0 bg-gradient-to-br from-blue-200/60 to-indigo-200/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-8 w-full max-w-md mx-4 shadow-xl">
            <h3 className="text-xl font-bold text-blue-800 mb-6">Add New Bike</h3>
            <form onSubmit={handleAddBike} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Bike Type</label>
                <select
                  value={newBike.type}
                  onChange={(e) => setNewBike({ ...newBike, type: e.target.value })}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                >
                  <option value="eBike">eBike</option>
                  <option value="Gyroscooter">Gyroscooter</option>
                  <option value="Segway">Segway</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Daily Rate ($)</label>
                <input
                  type="number"
                  value={newBike.dailyRate}
                  onChange={(e) => setNewBike({ ...newBike, dailyRate: e.target.value })}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">
                  Features (comma-separated)
                </label>
                <textarea
                  value={newBike.features}
                  onChange={(e) => setNewBike({ ...newBike, features: e.target.value })}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  placeholder="GPS, Height Adjustment, Speed Control"
                  rows={2}
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Number of Bikes</label>
                <input
                  type="number"
                  value={newBike.count}
                  onChange={(e) => setNewBike({ ...newBike, count: e.target.value })}
                  className="w-full p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>

              <div className="flex space-x-4 pt-4">
                <button
                  type="submit"
                  className="flex-1 bg-gradient-to-r from-blue-500 to-blue-600 text-white py-3 rounded-lg font-semibold hover:from-blue-600 hover:to-blue-700 transition-all"
                >
                  Add Bikes
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
}
