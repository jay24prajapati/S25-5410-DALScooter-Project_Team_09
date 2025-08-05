import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function OverviewSection({ tickets }) {
  const [stats, setStats] = useState({
    totalBikes: 0,
    activeBikes: 0,
    totalBookings: 0,
    totalRevenue: 0,
    uniqueCustomers: 0,
    confirmedBookings: 0,
    cancelledBookings: 0
  });

  const [openTickets, setOpenTickets] = useState(0);

  const token = localStorage.getItem('idToken');
  const franchiseId = localStorage.getItem('userId');

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await axios.get(`${API_BASE}/franchise/dashboard`, {
          headers: { Authorization: `Bearer ${token}` }
        });

        const bookingStats = res.data.bookingStatistics || {};
        const bikeStats = res.data.bikeStatistics || {};
        const statusBreakdown = bookingStats.statusBreakdown || {};

        setStats({
          totalBikes: bikeStats.totalBikeCount || 0,
          activeBikes: bikeStats.activeBikes || 0,
          totalBookings: bookingStats.totalBookings || 0,
          totalRevenue: bookingStats.totalRevenue || 0,
          uniqueCustomers: bookingStats.uniqueCustomers || 0,
          confirmedBookings: statusBreakdown.CONFIRMED || 0,
          cancelledBookings: statusBreakdown.CANCELLED || 0
        });
      } catch (err) {
        console.error('Failed to fetch dashboard stats:', err);
      }
    };

    fetchStats();
  }, [franchiseId]);

  useEffect(() => {
    setOpenTickets(tickets?.filter((t) => t.status === 'Open').length || 0);
  }, [tickets]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">
        {/* Total Bikes */}
        <StatCard title="Total Bikes" value={stats.totalBikes} color="blue" iconPath="M13 10V3L4 14h7v7l9-11h-7z" />

        {/* Active Bikes */}
        <StatCard title="Active Bikes" value={stats.activeBikes} color="green" iconPath="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />

        {/* Confirmed Bookings */}
        <StatCard title="Confirmed Bookings" value={stats.confirmedBookings} color="orange" iconPath="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />

        {/* Cancelled Bookings */}
        <StatCard title="Cancelled Bookings" value={stats.cancelledBookings} color="red" iconPath="M6 18L18 6M6 6l12 12" />

        {/* Total Revenue */}
        <StatCard title="Total Revenue" value={`$${stats.totalRevenue.toFixed(2)}`} color="purple" iconPath="M12 8c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z" />

        {/* Unique Customers */}
        <StatCard title="Unique Customers" value={stats.uniqueCustomers} color="indigo" iconPath="M16 14c2.21 0 4 1.79 4 4v1H4v-1c0-2.21 1.79-4 4-4h8zm-4-2c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z" />

        {/* Total Bookings */}
        <StatCard title="Total Bookings" value={stats.totalBookings} color="yellow" iconPath="M3 7h18M3 12h18M3 17h18" />

        {/* Open Tickets */}
        <StatCard title="Open Tickets" value={openTickets} color="pink" iconPath="M12 9v2m0 4h.01M6.938 19h10.124a2 2 0 001.732-2.5L13.732 4a2 2 0 00-3.464 0L5.206 16.5a2 2 0 001.732 2.5z" />
      </div>

      {/* You can insert a Revenue Chart or Recent Activity here if needed */}
    </div>
  );
}

// Reusable card component
function StatCard({ title, value, color, iconPath }) {
  const colors = {
    blue: 'from-blue-500 to-blue-600 text-blue-100',
    green: 'from-green-500 to-green-600 text-green-100',
    orange: 'from-orange-500 to-orange-600 text-orange-100',
    red: 'from-red-500 to-red-600 text-red-100',
    purple: 'from-purple-500 to-purple-600 text-purple-100',
    indigo: 'from-indigo-500 to-indigo-600 text-indigo-100',
    yellow: 'from-yellow-500 to-yellow-600 text-yellow-100',
    pink: 'from-pink-500 to-pink-600 text-pink-100'
  };

  const textColor = colors[color] || 'from-gray-500 to-gray-600 text-gray-100';

  return (
    <div className={`bg-gradient-to-r ${textColor} p-6 rounded-xl shadow-lg`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm">{title}</p>
          <p className="text-3xl font-bold text-white">{value}</p>
        </div>
        <svg className="w-10 h-10 text-white/60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={iconPath} />
        </svg>
      </div>
    </div>
  );
}
