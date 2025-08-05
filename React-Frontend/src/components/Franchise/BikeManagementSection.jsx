import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function BikeManagementSection() {
  const token = localStorage.getItem('idToken');
  const [bikes, setBikes] = useState([]);
  const [editBike, setEditBike] = useState(null);
  const [showAddBike, setShowAddBike] = useState(false);
  const [newBike, setNewBike] = useState({
    type: 'eBike',
    dailyRate: '',
    features: '',
    count: ''
  });

  useEffect(() => {
    fetchBikes();
  }, []);

  const fetchBikes = async () => {
    try {
      const today = new Date().toISOString().split('T')[0];
      const res = await axios.get(`${API_BASE}/bikes?date=${today}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setBikes(res.data);
    } catch (err) {
      console.error('Failed to load bikes:', err.response?.data || err.message);
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
      await axios.post(`${API_BASE}/bikes`, {
        type: newBike.type,
        dailyRate: parseFloat(newBike.dailyRate),
        features: newBike.features,
        count
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchBikes();
      setShowAddBike(false);
      setNewBike({ type: 'eBike', dailyRate: '', features: '', count: '' });
    } catch (err) {
      console.error('Failed to add bike:', err.response?.data || err.message);
      alert(`Add failed: ${err.message}`);
    }
  };

  const handleEditBike = async (e) => {
    e.preventDefault();
    const count = parseInt(editBike.count);
    if (isNaN(count) || count <= 0) {
      alert('Enter valid count');
      return;
    }

    try {
      await axios.put(`${API_BASE}/bikes/${editBike.bike_id}`, {
        dailyRate: parseFloat(editBike.dailyRate),
        features: editBike.features,
        count
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setEditBike(null);
      await fetchBikes();
    } catch (err) {
      console.error('Edit failed:', err.response?.data || err.message);
      alert(`Edit failed: ${err.message}`);
    }
  };

  const handleDeleteBike = async (bikeId) => {
    if (!confirm('Are you sure you want to delete this bike?')) return;
    try {
      await axios.delete(`${API_BASE}/bikes/${bikeId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchBikes();
    } catch (err) {
      console.error('Delete failed:', err.response?.data || err.message);
      alert(`Delete failed: ${err.message}`);
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
          <div key={bike.bike_id} className="bg-white rounded-xl shadow-lg border border-blue-100 overflow-hidden">
            <div className={`h-2 ${
              bike.type === 'eBike' ? 'bg-green-500' :
              bike.type === 'Gyroscooter' ? 'bg-blue-500' : 'bg-purple-500'
            }`}></div>
            <div className="p-6 space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="text-lg font-bold text-gray-800">{bike.bike_id}</h4>
                  <p className="text-blue-600 font-semibold">{bike.type}</p>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                  bike.available ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                }`}>
                  {bike.available ? 'Available' : 'Unavailable'}
                </span>
              </div>

              <div className="flex justify-between text-sm">
                <span>Available:</span>
                <span className="font-medium">{bike.availableCount} / {bike.totalCount}</span>
              </div>

              <div className="flex justify-between text-sm">
                <span>Daily Rate:</span>
                <span className="text-blue-700 font-semibold">${bike.dailyRate}</span>
              </div>

              <div>
                <p className="text-sm text-gray-600">Features:</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(typeof bike.features === 'string'
                    ? bike.features.split(',')
                    : Object.values(bike.features || {})
                  ).map((f, idx) => (
                    <span key={idx} className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full">
                      {f.trim()}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  onClick={() => setEditBike({
                    bike_id: bike.bike_id,
                    dailyRate: bike.dailyRate,
                    features: typeof bike.features === 'object'
                      ? Object.values(bike.features).join(', ')
                      : bike.features,
                    count: bike.totalCount
                  })}
                  className="text-blue-600 hover:underline text-sm"
                >
                  Edit
                </button>
                <button
                  onClick={() => handleDeleteBike(bike.bike_id)}
                  className="text-red-600 hover:underline text-sm"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Edit Modal */}
      {editBike && (
        <div className="fixed inset-0 bg-black bg-opacity-40 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white rounded-xl p-8 w-full max-w-md shadow-xl">
            <h3 className="text-xl font-bold text-blue-800 mb-4">Edit Bike</h3>
            <form onSubmit={handleEditBike} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Daily Rate ($)</label>
                <input
                  type="number"
                  value={editBike.dailyRate}
                  onChange={(e) => setEditBike({ ...editBike, dailyRate: e.target.value })}
                  className="w-full p-3 border border-blue-300 rounded-lg"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Features (comma-separated)</label>
                <textarea
                  rows={2}
                  value={editBike.features}
                  onChange={(e) => setEditBike({ ...editBike, features: e.target.value })}
                  className="w-full p-3 border border-blue-300 rounded-lg"
                  placeholder="GPS, Speed Control, Height Adjustment"
                />
              </div>

              <div>
                <label className="block text-sm font-semibold text-blue-700 mb-2">Total Count</label>
                <input
                  type="number"
                  value={editBike.count}
                  onChange={(e) => setEditBike({ ...editBike, count: e.target.value })}
                  className="w-full p-3 border border-blue-300 rounded-lg"
                  required
                />
              </div>

              <div className="flex justify-between pt-4">
                <button
                  type="submit"
                  className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
                >
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => setEditBike(null)}
                  className="bg-gray-300 text-gray-800 px-4 py-2 rounded-lg hover:bg-gray-400"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Bike Modal */}
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
                <label className="block text-sm font-semibold text-blue-700 mb-2">Features (comma-separated)</label>
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
