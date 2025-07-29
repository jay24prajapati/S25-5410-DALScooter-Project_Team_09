import React, { useEffect, useState } from 'react';
import '../styles/CustomerDashboard.css';


const scooterPrices = {
  ebike: 15,
  gyroscooter: 20,
  segway: 25,
};

export default function CustomerDashboard() {
  const [currentUser, setCurrentUser] = useState({});
  const [selectedScooterType, setSelectedScooterType] = useState('');
  const [duration, setDuration] = useState('');
  const [pickupLocation, setPickupLocation] = useState('');
  const [specialRequests, setSpecialRequests] = useState('');
  const [startTime, setStartTime] = useState('');
  const [bookings, setBookings] = useState([]);
  const [feedbacks, setFeedbacks] = useState([]);
  const [bookingResult, setBookingResult] = useState('');

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const user = {
      userId: urlParams.get('userId') || localStorage.getItem('dalscooter_userId'),
      email: urlParams.get('email') || localStorage.getItem('dalscooter_email'),
      userType: urlParams.get('userType') || localStorage.getItem('dalscooter_userType'),
      sessionId: urlParams.get('sessionId') || localStorage.getItem('dalscooter_sessionId'),
    };
    if (!user.userId || !user.email) {
      window.location.href = '/';
    } else if (user.userType === 'franchise') {
      window.location.href = `/franchise-dashboard?${urlParams.toString()}`;
    } else {
      setCurrentUser(user);
    }
  }, []);

  const handleBooking = (e) => {
    e.preventDefault();
    if (!selectedScooterType || !pickupLocation || !duration || !startTime) {
      alert('Fill all required fields.');
      return;
    }
    const id = `DAL-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 5)}`.toUpperCase();
    const booking = {
      bookingId: id,
      scooterType: selectedScooterType,
      pickupLocation,
      startTime,
      duration,
      specialRequests,
    };
    setBookings([...bookings, booking]);
    setBookingResult(`Booking Confirmed! Booking ID: ${id}`);
  };

  const handleScooterSelect = (type) => {
    setSelectedScooterType(type);
    setBookingResult('');
  };

  const totalCost = selectedScooterType && duration ? scooterPrices[selectedScooterType] * parseInt(duration) : 0;

  return (
    <div className="customer-dashboard">
      <header className="dashboard-header">
        <h1>DALScooter | Customer Dashboard</h1>
        <div>Welcome, {currentUser.email}</div>
      </header>

      <main className="dashboard-main">
        <h2>Choose Your Scooter</h2>
        <div className="scooter-types">
          {['ebike', 'gyroscooter', 'segway'].map((type) => (
            <div key={type}
              className={`scooter-card ${selectedScooterType === type ? 'selected' : ''}`}
              onClick={() => handleScooterSelect(type)}
            >
              <h3>{type.charAt(0).toUpperCase() + type.slice(1)}</h3>
              <p>${scooterPrices[type]}/hour</p>
            </div>
          ))}
        </div>

        {selectedScooterType && (
          <form className="booking-form" onSubmit={handleBooking}>
            <h3>Booking Form</h3>
            <input value={pickupLocation} onChange={(e) => setPickupLocation(e.target.value)} placeholder="Pickup Location" />
            <input type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)} />
            <select value={duration} onChange={(e) => setDuration(e.target.value)}>
              <option value="">Select Duration</option>
              {[1, 2, 3, 4, 6, 8].map((d) => (
                <option key={d} value={d}>{d} hour{d > 1 ? 's' : ''}</option>
              ))}
            </select>
            <textarea placeholder="Special Requests (optional)" value={specialRequests} onChange={(e) => setSpecialRequests(e.target.value)}></textarea>
            <p>Total: ${totalCost.toFixed(2)}</p>
            <button type="submit">Book Now</button>
          </form>
        )}

        {bookingResult && <div className="result-box success">{bookingResult}</div>}
      </main>
    </div>
  );
}
