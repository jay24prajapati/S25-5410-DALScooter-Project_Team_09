import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import VirtualAssistant from '../components/VirtualAssistant'

const LandingPage = () => {
    const [isMenuOpen, setIsMenuOpen] = useState(false)
    const [currentBike, setCurrentBike] = useState(0)
    const [bikes, setBikes] = useState([])
    const [bikeFeedback, setBikeFeedback] = useState({})
    const [loading, setLoading] = useState(true)
    const navigate = useNavigate()

    const API_BASE = import.meta.env.VITE_API_BASE

    // Fetch bikes from API
    const fetchBikes = async () => {
        try {
            const response = await fetch(`${API_BASE}/bikes`)
            const data = await response.json()
            setBikes(data)
        } catch (error) {
            console.error('Error fetching bikes:', error)
        }
    }

    // Fetch feedback for all bikes
    const fetchBikeFeedback = async () => {
        try {
            if (bikes.length === 0) return

            const feedbackPromises = bikes.map(async (bike) => {
                try {
                    const response = await fetch(`${API_BASE}/bikes/${bike.bike_id}/feedback`)
                    const data = await response.json()
                    return { bikeId: bike.bike_id, feedback: data }
                } catch (err) {
                    console.error(`Failed to fetch feedback for bike ${bike.bike_id}:`, err)
                    return { bikeId: bike.bike_id, feedback: null }
                }
            })

            const results = await Promise.all(feedbackPromises)
            const feedbackMap = {}
            results.forEach(({ bikeId, feedback }) => {
                feedbackMap[bikeId] = feedback
            })
            setBikeFeedback(feedbackMap)
        } catch (error) {
            console.error('Error fetching bike feedback:', error)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchBikes()
    }, [])

    useEffect(() => {
        if (bikes.length > 0) {
            fetchBikeFeedback()
        }
    }, [bikes])

    // Auto-rotate bike showcase
    useEffect(() => {
        if (bikes.length > 0) {
            const interval = setInterval(() => {
                setCurrentBike((prev) => (prev + 1) % bikes.length)
            }, 5000)
            return () => clearInterval(interval)
        }
    }, [bikes])

    const scrollToSection = (sectionId) => {
        document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth' })
        setIsMenuOpen(false)
    }

    const handleGetStarted = () => {
        navigate('/register')
    }

    const handleLogin = () => {
        navigate('/login')
    }

    // Get recent feedback for display
    const getAllRecentFeedback = () => {
        const allFeedback = []
        Object.entries(bikeFeedback).forEach(([bikeId, data]) => {
            if (data?.feedback?.length > 0) {
                const bike = bikes.find(b => b.bike_id === bikeId)
                data.feedback.forEach(feedback => {
                    allFeedback.push({
                        ...feedback,
                        bikeName: bike?.type || 'Unknown',
                        bikeId
                    })
                })
            }
        })
        return allFeedback.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 6)
    }

    const renderStars = (rating) => {
        return Array.from({ length: 5 }, (_, i) => (
            <span key={i} className={`text-lg ${i < rating ? 'text-yellow-500' : 'text-gray-300'}`}>
                ★
            </span>
        ))
    }

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        })
    }

    const getBikeColor = (type) => {
        switch (type.toLowerCase()) {
            case 'segway':
                return 'from-blue-400 to-indigo-500'
            case 'gyroscooter':
                return 'from-purple-400 to-pink-500'
            case 'ebike':
                return 'from-green-400 to-blue-500'
            default:
                return 'from-gray-400 to-gray-500'
        }
    }

    // Group bikes by type for pricing
    const groupedBikes = bikes.reduce((acc, bike) => {
        if (!acc[bike.type]) {
            acc[bike.type] = bike
        }
        return acc
    }, {})

    const totalAvailable = bikes.reduce((sum, bike) => sum + bike.availableCount, 0)
    const uniqueTypes = [...new Set(bikes.map(bike => bike.type))].length

    return (
        <div className="min-h-screen bg-white">
            {/* Navigation */}
            <nav className="fixed top-0 w-full bg-white/95 backdrop-blur-sm border-b border-gray-200 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-2">
                            <span className="text-xl font-bold text-blue-600">DALScooter</span>
                        </div>

                        {/* Desktop Menu */}
                        <div className="hidden md:flex items-center space-x-8">
                            <button onClick={() => scrollToSection('bikes')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Fleet
                            </button>
                            <button onClick={() => scrollToSection('reviews')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Reviews
                            </button>
                            <button onClick={() => scrollToSection('contact')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Contact
                            </button>
                            <button onClick={handleLogin} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Login
                            </button>
                            <button onClick={handleGetStarted} className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                                Sign Up
                            </button>
                        </div>

                        {/* Mobile Menu Button */}
                        <div className="md:hidden">
                            <button
                                onClick={() => setIsMenuOpen(!isMenuOpen)}
                                className="text-gray-700 hover:text-blue-600"
                            >
                                {isMenuOpen ? '✕' : '☰'}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Mobile Menu */}
                {isMenuOpen && (
                    <div className="md:hidden bg-white border-t border-gray-200">
                        <div className="px-2 pt-2 pb-3 space-y-1">
                            <button onClick={() => scrollToSection('bikes')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Fleet
                            </button>
                            <button onClick={() => scrollToSection('reviews')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Reviews
                            </button>
                            <button onClick={() => scrollToSection('contact')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Contact
                            </button>
                            <button onClick={handleLogin} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Login
                            </button>
                            <button onClick={handleGetStarted} className="block w-full text-left px-3 py-2 text-blue-600 font-semibold">
                                Sign Up
                            </button>
                        </div>
                    </div>
                )}
            </nav>

            {/* Hero Section */}
            <section className="pt-16 bg-gradient-to-br from-blue-50 to-indigo-100">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
                    <div className="text-center">
                        <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
                            Electric Scooter Rentals
                            <span className="text-blue-600"> in Halifax</span>
                        </h1>
                        <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
                            Rent electric scooters and bikes for your daily commute or weekend adventures. 
                            Easy booking and reliable service.
                        </p>
                        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-12">
                            <button onClick={handleGetStarted} className="bg-blue-600 text-white px-8 py-4 rounded-lg text-lg font-semibold hover:bg-blue-700 transition-colors">
                                Book Now
                            </button>
                            <button onClick={() => scrollToSection('bikes')} className="border border-gray-300 text-gray-700 px-8 py-4 rounded-lg text-lg font-semibold hover:bg-gray-50 transition-colors">
                                View Fleet →
                            </button>
                        </div>

                        {/* Dynamic Stats */}
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-6 max-w-2xl mx-auto">
                            <div className="text-center">
                                <div className="text-3xl font-bold text-blue-600">{totalAvailable}</div>
                                <div className="text-sm text-gray-600">Available Now</div>
                            </div>
                            <div className="text-center">
                                <div className="text-3xl font-bold text-green-600">{uniqueTypes}</div>
                                <div className="text-sm text-gray-600">Vehicle Types</div>
                            </div>
                            <div className="text-center">
                                <div className="text-3xl font-bold text-purple-600">24/7</div>
                                <div className="text-sm text-gray-600">Service</div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Fleet Section */}
            <section id="bikes" className="py-20 bg-white">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            Our Fleet
                        </h2>
                        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                            Choose from our selection of electric vehicles
                        </p>
                    </div>

                    <div className="grid md:grid-cols-3 gap-8">
                        {bikes.map((bike, index) => {
                            const feedback = bikeFeedback[bike.bike_id]
                            const avgRating = feedback?.statistics?.averageRating || 0
                            const totalReviews = feedback?.statistics?.totalFeedback || 0
                            
                            return (
                                <div
                                    key={bike.bike_id}
                                    className={`rounded-2xl p-6 border-2 transition-all duration-300 cursor-pointer ${
                                        currentBike === index ? 'border-blue-500 shadow-xl' : 'border-gray-200 hover:border-gray-300'
                                    }`}
                                    onClick={() => setCurrentBike(index)}
                                >
                                    <div className={`w-16 h-16 rounded-full bg-gradient-to-r ${getBikeColor(bike.type)} mb-4`}></div>
                                    <h3 className="text-2xl font-bold text-gray-900 mb-2">{bike.type}</h3>
                                    <p className="text-gray-600 mb-4">{bike.features}</p>
                                    
                                    <div className="flex justify-between items-center mb-4">
                                        <span className="text-2xl font-bold text-blue-600">${bike.dailyRate}/day</span>
                                        <span className="text-sm text-green-600 bg-green-50 px-2 py-1 rounded-full">
                                            {bike.availableCount} available
                                        </span>
                                    </div>

                                    {totalReviews > 0 && (
                                        <div className="flex items-center space-x-1">
                                            {renderStars(Math.round(avgRating))}
                                            <span className="text-sm text-gray-600 ml-2">
                                                ({totalReviews} {totalReviews === 1 ? 'review' : 'reviews'})
                                            </span>
                                        </div>
                                    )}
                                </div>
                            )
                        })}
                    </div>
                </div>
            </section>

            {/* Customer Reviews Section */}
            <section id="reviews" className="py-20 bg-gray-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            Customer Reviews
                        </h2>
                        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                            See what our customers are saying
                        </p>
                    </div>

                    {loading ? (
                        <div className="text-center py-8">
                            <div className="text-gray-600">Loading reviews...</div>
                        </div>
                    ) : (
                        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
                            {getAllRecentFeedback().map((review, index) => (
                                <div key={review.feedback_id} className="bg-white rounded-lg p-6 shadow-md">
                                    <div className="flex items-center justify-between mb-4">
                                        <div className="flex items-center space-x-1">
                                            {renderStars(review.rating)}
                                        </div>
                                        <span className="text-sm text-gray-500">
                                            {formatDate(review.createdAt)}
                                        </span>
                                    </div>
                                    <p className="text-gray-800 mb-3">"{review.comment}"</p>
                                    <div className="text-sm text-gray-600">
                                        <span className="font-semibold">{review.bikeName}</span>
                                        <span className={`ml-2 px-2 py-1 rounded-full text-xs ${
                                            review.sentiment === 'positive' ? 'bg-green-100 text-green-800' :
                                            review.sentiment === 'negative' ? 'bg-red-100 text-red-800' :
                                            'bg-gray-100 text-gray-800'
                                        }`}>
                                            {review.sentiment}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}

                    {getAllRecentFeedback().length === 0 && !loading && (
                        <div className="text-center py-8">
                            <p className="text-gray-600">No reviews available yet. Be the first to leave a review!</p>
                        </div>
                    )}
                </div>
            </section>

            {/* Contact Section */}
            <section id="contact" className="py-20 bg-white">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            Get in Touch
                        </h2>
                        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                            Questions? We're here to help
                        </p>
                    </div>

                    <div className="grid md:grid-cols-2 gap-8 max-w-2xl mx-auto">
                        <div className="text-center p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-2">Customer Support</h3>
                            <p className="text-gray-600 mb-2">support@dalscooter.com</p>
                            <p className="text-sm text-gray-500">Available 24/7</p>
                        </div>
                        <div className="text-center p-6">
                            <h3 className="text-lg font-semibold text-gray-900 mb-2">Location</h3>
                            <p className="text-gray-600 mb-2">Halifax, Nova Scotia</p>
                            <p className="text-sm text-gray-500">Multiple pickup locations</p>
                        </div>
                    </div>

                    <div className="text-center mt-12">
                        <button onClick={handleGetStarted} className="bg-blue-600 text-white px-8 py-3 rounded-lg text-lg font-semibold hover:bg-blue-700 transition-colors">
                            Get Started Today
                        </button>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="bg-gray-900 text-white py-12">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="grid md:grid-cols-3 gap-8">
                        <div>
                            <span className="text-xl font-bold">DALScooter</span>
                            <p className="text-gray-400 mt-4 mb-4">
                                Electric scooter rentals in Halifax, Nova Scotia.
                            </p>
                            <div className="text-sm text-gray-500">
                                © 2025 DALScooter. All rights reserved.
                            </div>
                        </div>
                        <div>
                            <h4 className="text-lg font-semibold mb-4">Services</h4>
                            <ul className="space-y-2 text-gray-400">
                                {Object.keys(groupedBikes).map(type => (
                                    <li key={type}>{type} Rentals</li>
                                ))}
                            </ul>
                        </div>
                        <div>
                            <h4 className="text-lg font-semibold mb-4">Contact</h4>
                            <ul className="space-y-2 text-gray-400">
                                <li>support@dalscooter.com</li>
                                <li>Halifax, Nova Scotia</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </footer>

            <VirtualAssistant />
        </div>
    )
}

export default LandingPage
