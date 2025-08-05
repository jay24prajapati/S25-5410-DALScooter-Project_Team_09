const API_BASE_URL = import.meta.env.VITE_API_BASE;
import React, { useEffect, useState } from 'react';
import axios from 'axios';

const CustomerProfile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem('idToken');
        const res = await axios.get(`${API_BASE_URL}/customers/profile`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        setProfile(res.data);
      } catch (error) {
        console.error('Error fetching customer profile:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-16 space-y-4">
        <div className="animate-spin rounded-full h-12 w-12 border-b-4 border-blue-600"></div>
        <p className="text-gray-600">Loading your profile...</p>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="text-center py-16">
        <div className="text-6xl mb-4"></div>
        <p className="text-xl text-gray-500 mb-2">Profile not found</p>
        <p className="text-gray-400">Please try refreshing the page</p>
      </div>
    );
  }

  const profileFields = [
    
    {
      icon: '',
      label: 'Email Address',
      value: profile.email,
      type: 'text'
    },
    {
      icon: '',
      label: 'User Type',
      value: profile.userType,
      type: 'badge',
      badgeColor: 'from-blue-500 to-indigo-500'
    },
    {
      icon: '',
      label: 'Member Since',
      value: new Date(profile.registrationDate).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      }),
      type: 'text'
    },
    {
      icon: '',
      label: 'Account Status',
      value: profile.isActive ? 'Active' : 'Inactive',
      type: 'status',
      status: profile.isActive ? 'active' : 'inactive'
    },
    {
      icon: '',
      label: 'Verification Status',
      value: profile.verificationStatus,
      type: 'badge',
      badgeColor: profile.verificationStatus === 'verified' 
        ? 'from-green-500 to-emerald-500' 
        : 'from-orange-500 to-yellow-500'
    }
  ];

  return (
    <div className="space-y-8">
      {/* Profile Header */}
      <div className="text-center pb-8 border-b border-gray-200">
        <div className="w-24 h-24 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center mx-auto mb-4 shadow-xl">
          <span className="text-white text-3xl font-bold">
            {profile.email.charAt(0).toUpperCase()}
          </span>
        </div>
        <h3 className="text-2xl font-bold text-gray-800 mb-2">
          Welcome back, {profile.email.split('@')[0]}!
        </h3>
        <p className="text-gray-500">
          Your DALScooter customer profile
        </p>
      </div>

      {/* Profile Information Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {profileFields.map((field, index) => (
          <div
            key={index}
            className="bg-gradient-to-r from-white/50 to-white/30 backdrop-blur-sm rounded-xl p-6 border border-white/20 shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
          >
            <div className="flex items-start space-x-4">
              <div className="text-3xl">{field.icon}</div>
              <div className="flex-1 min-w-0">
                <h4 className="text-sm font-semibold text-gray-600 uppercase tracking-wide mb-2">
                  {field.label}
                </h4>
                
                {field.type === 'text' && (
                  <p className="text-lg font-medium text-gray-800 break-all">
                    {field.value}
                  </p>
                )}
                
                {field.type === 'badge' && (
                  <span className={`inline-flex items-center px-4 py-2 rounded-full text-white font-semibold text-sm bg-gradient-to-r ${field.badgeColor} shadow-lg`}>
                    {field.value}
                  </span>
                )}
                
                {field.type === 'status' && (
                  <div className="flex items-center space-x-2">
                    <div className={`w-3 h-3 rounded-full ${
                      field.status === 'active' ? 'bg-green-400' : 'bg-red-400'
                    } animate-pulse`}></div>
                    <span className={`font-semibold ${
                      field.status === 'active' ? 'text-green-600' : 'text-red-600'
                    }`}>
                      {field.value}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Account Stats */}
      <div className="bg-gradient-to-r from-blue-50 to-purple-50 rounded-xl p-6 border border-blue-100">
        <h4 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
          <span className="text-2xl"></span>
          <span>Account Summary</span>
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          
          <div className="text-center bg-white/60 rounded-lg p-4">
            <div className="text-2xl font-bold text-green-600 mb-1">
              {profile.isActive ? '✓' : '✗'}
            </div>
            <div className="text-sm text-gray-600">Account Active</div>
          </div>
          <div className="text-center bg-white/60 rounded-lg p-4">
            <div className="text-2xl font-bold text-purple-600 mb-1">
              {profile.verificationStatus === 'verified' ? '✓' : '⏳'}
            </div>
            <div className="text-sm text-gray-600">Verified Status</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CustomerProfile;