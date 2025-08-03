import React from 'react';

export default function BookingSection({ bookings, bikes, getBikeByBookingRef }) {
  return (
    <div className="space-y-6">
      <h3 className="text-2xl font-bold text-blue-800">Booking Management</h3>

      <div className="bg-white rounded-xl shadow-lg border border-blue-100">
        {/* Booking Lookup */}
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

        {/* Booking Table */}
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
              {bookings.map((booking) => {
                const bike = bikes.find((b) => b.id === booking.bikeId);
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
}
