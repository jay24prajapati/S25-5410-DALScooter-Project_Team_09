const API_BASE_URL = import.meta.env.VITE_API_BASE;
import React, { useEffect, useState } from 'react';
import axios from 'axios';

const CustomerProfile = () => {
  const [profile, setProfile] = useState(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const token = localStorage.getItem('idToken');
        const res = await axios.get(`${API_BASE_URL}/customers/profile`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        setProfile(res.data);
      } catch (error) {
        console.error('Error fetching customer profile:', error);
      }
    };

    fetchProfile();
  }, []);

  if (!profile) return <div className="p-4">Loading profile...</div>;

  return (
    <div className="bg-white shadow-md rounded-lg p-6 max-w-xl mx-auto mt-6">
      <h2 className="text-xl font-semibold mb-4">Customer Profile</h2>
      <p><strong>Email:</strong> {profile.email}</p>
      <p><strong>User Type:</strong> {profile.userType}</p>
      <p><strong>Registered On:</strong> {new Date(profile.registrationDate).toLocaleDateString()}</p>
      <p><strong>Status:</strong> {profile.isActive ? 'Active' : 'Inactive'}</p>
      <p><strong>Verification:</strong> {profile.verificationStatus}</p>
    </div>
  );
};


export default CustomerProfile;
