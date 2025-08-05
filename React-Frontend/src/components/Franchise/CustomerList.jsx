import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function CustomerList() {
  const [customers, setCustomers] = useState([]);
  const token = localStorage.getItem('idToken');

  useEffect(() => {
    axios.get(`${API_BASE}/franchise/customers`, {
      headers: { Authorization: `Bearer ${token}` }
    })
    .then(res => setCustomers(res.data.customers))
    .catch(err => console.error('Failed to fetch customers:', err));
  }, []);

  return (
    <div className="p-6 bg-white rounded-xl shadow-lg border border-blue-100">
      <h2 className="text-2xl font-bold text-blue-800 mb-6">Registered Customers</h2>
      <ul className="space-y-4">
        {customers.map(c => (
          <li key={c.customer_id} className="p-4 border rounded-lg bg-blue-50/30">
            <div className="font-semibold text-blue-800">{c.email}</div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 mt-2 text-sm text-gray-700">
              <div><strong>Total Bookings:</strong> {c.totalBookings}</div>
              <div><strong>Total Revenue:</strong> ${c.totalRevenue.toFixed(2)}</div>
              <div><strong>Registered:</strong> {c.registrationDate}</div>
<div><strong>First Booking:</strong> {c.firstBooking}</div>
<div><strong>Last Booking:</strong> {c.lastBooking}</div>

              <div>
                <strong>Status Breakdown:</strong>
                <ul className="list-disc list-inside ml-2 text-xs text-gray-600">
                  {Object.entries(c.bookingStatuses || {}).map(([status, count]) => (
                    <li key={status}>{status}: {count}</li>
                  ))}
                </ul>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
