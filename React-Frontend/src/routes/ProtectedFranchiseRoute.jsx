import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';
import { toast } from 'react-toastify';

const isTokenExpired = (token) => {
  try {
    const decoded = jwtDecode(token);
    const currentTime = Math.floor(Date.now() / 1000); // seconds
    return decoded.exp < currentTime;
  } catch (err) {
    return true; // treat invalid token as expired
  }
};

const ProtectedFranchiseRoute = ({ children }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const accessToken = localStorage.getItem('accessToken');
    const sessionId = localStorage.getItem('sessionId');
    const userType = localStorage.getItem('userType');

    if (
      !accessToken ||
      !sessionId ||
      userType !== 'franchise' ||
      isTokenExpired(accessToken)
    ) {
      toast.warn('Session expired or unauthorized access. Please log in again.');
      localStorage.clear();
      navigate('/login');
    } else {
      setLoading(false);
    }
  }, [navigate]);

  if (loading)
    return (
      <div className="text-center mt-10 text-blue-600 font-semibold">
        Checking credentials...
      </div>
    );

  return children;
};

export default ProtectedFranchiseRoute;
