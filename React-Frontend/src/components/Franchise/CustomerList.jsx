import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerList() {
  const [customers, setCustomers] = useState([]);
  const token = localStorage.getItem('idToken'); // ✅ Grab token from storage

  useEffect(() => {
    axios.get(`${API_BASE}/franchise/customers`, {
      headers: {
        Authorization: `Bearer ${token}` // ✅ Add Authorization header
      }
    })
    .then(res => setCustomers(res.data.customers))
    .catch(err => console.error('Failed to fetch customers:', err));
  }, []);

  return (
    <div className="p-4 bg-white rounded-xl shadow-lg">
      <h2 className="text-xl font-bold mb-4">Registered Customers</h2>
      <ul className="space-y-3">
        {customers.map(c => (
          <li key={c.customer_id} className="p-4 border rounded-lg bg-gray-50">
            <div className="font-semibold">{c.email}</div>
            <div className="text-sm text-gray-600">
              Total Bookings: {c.totalBookings} | Revenue: ${c.totalRevenue}
            </div>
            <div className="text-xs text-gray-400">
              Registered on: {new Date(c.registrationDate).toLocaleDateString()}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
