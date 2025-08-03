import React, { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE;

export default function OverviewSection({ bookings, tickets }) {
  const [totalCount, setTotalCount] = useState(0);
  const [availableCount, setAvailableCount] = useState(0);
  const [activeBookings, setActiveBookings] = useState(0);
  const [openTickets, setOpenTickets] = useState(0);

  const franchiseId = localStorage.getItem('franchise_id'); // Or get from auth context

  useEffect(() => {
    const fetchDashboardStats = async () => {
      try {
        const res = await axios.post(`${API_BASE}/franchise/dashboard`, {
          franchise_id: franchiseId,
        });

        const bikeStats = res.data.bikeStatistics || {};
        const bookingStats = res.data.bookingStatistics || {};

        setTotalCount(bikeStats.totalBikeCount || 0);
        setAvailableCount(bikeStats.activeBikes || 0);

        setActiveBookings(bookingStats.statusBreakdown?.CONFIRMED || 0);
      } catch (err) {
        console.error('Failed to fetch dashboard stats:', err);
      }
    };

    fetchDashboardStats();
  }, [franchiseId]);

  useEffect(() => {
    setOpenTickets(tickets.filter((t) => t.status === 'Open').length);
  }, [tickets]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Total Bikes */}
        <div className="bg-gradient-to-r from-blue-500 to-blue-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm">Total Bikes</p>
              <p className="text-3xl font-bold">{totalCount}</p>
            </div>
            <svg className="w-12 h-12 text-blue-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
        </div>

        {/* Available Bikes */}
        <div className="bg-gradient-to-r from-green-500 to-green-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-100 text-sm">Available</p>
              <p className="text-3xl font-bold">{availableCount}</p>
            </div>
            <svg className="w-12 h-12 text-green-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>

        {/* Active Bookings */}
        <div className="bg-gradient-to-r from-orange-500 to-orange-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-orange-100 text-sm">Active Bookings</p>
              <p className="text-3xl font-bold">{activeBookings}</p>
            </div>
            <svg className="w-12 h-12 text-orange-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>

        {/* Open Tickets */}
        <div className="bg-gradient-to-r from-red-500 to-red-600 text-white p-6 rounded-xl shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-100 text-sm">Open Tickets</p>
              <p className="text-3xl font-bold">{openTickets}</p>
            </div>
            <svg className="w-12 h-12 text-red-200" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.728-.833-2.498 0L4.316 15.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
        </div>
      </div>

      {/* Static Recent Activity */}
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
}
