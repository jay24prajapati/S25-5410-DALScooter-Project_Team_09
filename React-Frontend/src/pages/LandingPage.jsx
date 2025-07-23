import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
    Zap,
    Shield,
    Star,
    MapPin,
    Clock,
    DollarSign,
    Users,
    MessageCircle,
    ChevronDown,
    Menu,
    X,
    Play,
    ArrowRight
} from 'lucide-react'
import VirtualAssistant from '../components/VirtualAssistant'

const LandingPage = () => {
    const [isMenuOpen, setIsMenuOpen] = useState(false)
    const [currentBike, setCurrentBike] = useState(0)
    const navigate = useNavigate()

    const bikeTypes = [
        {
            id: 'ebike',
            name: 'eBike',
            type: 'Electric Bicycle',
            description: 'Eco-friendly electric bicycle with pedal assist technology',
            price: '$15/hour',
            features: ['Long Battery Life', 'Eco-Friendly', 'Pedal Assist', 'Lightweight'],
            icon: '🚲',
            color: 'from-green-400 to-blue-500',
            availability: 8
        },
        {
            id: 'gyroscooter',
            name: 'Gyroscooter',
            type: 'Self-Balancing Scooter',
            description: 'Advanced self-balancing electric scooter for smooth rides',
            price: '$20/hour',
            features: ['Self-Balancing', 'Fast Speed', 'Smart Control', 'Stable Ride'],
            icon: '🛴',
            color: 'from-purple-400 to-pink-500',
            availability: 12
        },
        {
            id: 'segway',
            name: 'Segway',
            type: 'Premium Transporter',
            description: 'Premium personal transporter with advanced safety features',
            price: '$25/hour',
            features: ['Premium Quality', 'Extra Safe', 'Long Range', 'Comfortable'],
            icon: '🛵',
            color: 'from-yellow-400 to-orange-500',
            availability: 4
        }
    ]

    const userTypes = [
        {
            type: 'Guest Users',
            description: 'Explore without registration',
            features: [
                'Check bike availability and tariffs',
                'View customer feedback and ratings',
                'Use virtual assistant for navigation',
                'Browse all bike types'
            ],
            icon: '👤',
            color: 'bg-blue-50 border-blue-200',
            buttonText: 'Browse as Guest',
            buttonColor: 'btn-secondary'
        },
        {
            type: 'Registered Customers',
            description: 'Full access with secure authentication',
            features: [
                'Multi-factor authentication security',
                'Reserve bikes for specific periods',
                'Get booking notifications',
                'Provide feedback and ratings',
                'Access virtual assistant features',
                'Customer support messaging'
            ],
            icon: '🔐',
            color: 'bg-green-50 border-green-200',
            buttonText: 'Sign Up Now',
            buttonColor: 'btn-primary',
            popular: true
        },
        {
            type: 'Franchise Operators',
            description: 'Admin access for business management',
            features: [
                'Add and manage bike inventory',
                'Set pricing and discount codes',
                'View analytics and statistics',
                'Handle customer communications',
                'Multi-factor authentication',
                'Advanced dashboard features'
            ],
            icon: '👑',
            color: 'bg-purple-50 border-purple-200',
            buttonText: 'Franchise Portal',
            buttonColor: 'btn-secondary'
        }
    ]

    // Auto-rotate bike showcase
    useEffect(() => {
        const interval = setInterval(() => {
            setCurrentBike((prev) => (prev + 1) % bikeTypes.length)
        }, 4000)
        return () => clearInterval(interval)
    }, [])

    const scrollToSection = (sectionId) => {
        document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth' })
        setIsMenuOpen(false)
    }

    const handleGetStarted = () => {
        navigate('/auth')
    }

    return (
        <div className="min-h-screen bg-white">
            {/* Navigation */}
            <nav className="fixed top-0 w-full bg-white/95 backdrop-blur-sm border-b border-gray-200 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-2">
                            <div className="text-2xl">🛴</div>
                            <span className="text-xl font-bold text-gradient">DALScooter</span>
                        </div>

                        {/* Desktop Menu */}
                        <div className="hidden md:flex items-center space-x-8">
                            <button onClick={() => scrollToSection('bikes')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Bikes
                            </button>
                            <button onClick={() => scrollToSection('features')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Features
                            </button>
                            <button onClick={() => scrollToSection('pricing')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Pricing
                            </button>
                            <button onClick={() => scrollToSection('contact')} className="text-gray-700 hover:text-blue-600 transition-colors">
                                Contact
                            </button>
                            <button onClick={handleGetStarted} className="btn-primary">
                                Get Started
                            </button>
                        </div>

                        {/* Mobile Menu Button */}
                        <div className="md:hidden">
                            <button
                                onClick={() => setIsMenuOpen(!isMenuOpen)}
                                className="text-gray-700 hover:text-blue-600"
                            >
                                {isMenuOpen ? <X size={24} /> : <Menu size={24} />}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Mobile Menu */}
                {isMenuOpen && (
                    <div className="md:hidden bg-white border-t border-gray-200">
                        <div className="px-2 pt-2 pb-3 space-y-1">
                            <button onClick={() => scrollToSection('bikes')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Bikes
                            </button>
                            <button onClick={() => scrollToSection('features')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Features
                            </button>
                            <button onClick={() => scrollToSection('pricing')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Pricing
                            </button>
                            <button onClick={() => scrollToSection('contact')} className="block px-3 py-2 text-gray-700 hover:text-blue-600">
                                Contact
                            </button>
                            <button onClick={handleGetStarted} className="block w-full text-left px-3 py-2 text-blue-600 font-semibold">
                                Get Started
                            </button>
                        </div>
                    </div>
                )}
            </nav>

            {/* Hero Section */}
            <section className="pt-16 gradient-bg">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
                    <div className="text-center">
                        <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6 animate-fade-in">
                            Premium Electric Scooter
                            <span className="text-gradient"> Rentals</span>
                        </h1>
                        <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto animate-slide-up">
                            Experience the future of urban mobility with our fleet of eBikes, Gyroscooters, and Segways.
                            Eco-friendly, secure, and available 24/7 with advanced booking system.
                        </p>
                        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mb-8">
                            <button onClick={handleGetStarted} className="btn-primary text-lg px-8 py-4">
                                <Play className="w-5 h-5 mr-2" />
                                Start Your Journey
                            </button>
                            <button onClick={() => scrollToSection('bikes')} className="btn-secondary text-lg px-8 py-4">
                                Explore Fleet
                                <ArrowRight className="w-5 h-5 ml-2" />
                            </button>
                        </div>

                        {/* Virtual Assistant Notice */}
                        <div className="mb-12">
                            <div className="inline-flex items-center bg-blue-50 border border-blue-200 rounded-full px-4 py-2 text-sm text-blue-700">
                                <MessageCircle className="w-4 h-4 mr-2" />
                                <span>Need help? Chat with our virtual assistant (bottom right) - No registration required!</span>
                            </div>
                        </div>

                        {/* Hero Stats */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto">
                            <div className="text-center">
                                <div className="text-2xl font-bold text-blue-600">24+</div>
                                <div className="text-sm text-gray-600">Available Scooters</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-green-600">3</div>
                                <div className="text-sm text-gray-600">Vehicle Types</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-purple-600">24/7</div>
                                <div className="text-sm text-gray-600">Service Available</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-orange-600">100%</div>
                                <div className="text-sm text-gray-600">Electric Powered</div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Scroll Indicator */}
                <div className="text-center pb-8">
                    <ChevronDown className="w-6 h-6 text-gray-400 animate-bounce mx-auto cursor-pointer"
                                 onClick={() => scrollToSection('bikes')} />
                </div>
            </section>

            {/* Bike Showcase Section */}
            <section id="bikes" className="py-20 bg-white">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            Choose Your Perfect Ride
                        </h2>
                        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                            Our diverse fleet offers something for everyone, from eco-friendly eBikes to premium Segways
                        </p>
                    </div>

                    <div className="grid md:grid-cols-3 gap-8">
                        {bikeTypes.map((bike, index) => (
                            <div
                                key={bike.id}
                                className={`card-hover rounded-2xl p-6 border-2 transition-all duration-300 ${
                                    currentBike === index ? 'border-blue-500 shadow-xl scale-105' : 'border-gray-200'
                                }`}
                                onClick={() => setCurrentBike(index)}
                            >
                                <div className={`w-16 h-16 rounded-full bg-gradient-to-r ${bike.color} flex items-center justify-center text-2xl mb-4`}>
                                    {bike.icon}
                                </div>
                                <h3 className="text-2xl font-bold text-gray-900 mb-2">{bike.name}</h3>
                                <p className="text-gray-600 mb-4">{bike.description}</p>
                                <div className="flex justify-between items-center mb-4">
                                    <span className="text-2xl font-bold text-blue-600">{bike.price}</span>
                                    <span className="text-sm text-green-600 bg-green-50 px-2 py-1 rounded-full">
                    {bike.availability} available
                  </span>
                                </div>
                                <div className="space-y-2">
                                    {bike.features.map((feature, idx) => (
                                        <div key={idx} className="flex items-center text-sm text-gray-600">
                                            <Star className="w-4 h-4 text-yellow-400 mr-2" />
                                            {feature}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* User Types Section */}
            <section id="features" className="py-20 gradient-bg">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            Designed for Every User
                        </h2>
                        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                            Whether you're browsing, booking, or managing a fleet, we have the perfect solution
                        </p>
                    </div>

                    <div className="grid md:grid-cols-3 gap-8">
                        {userTypes.map((user, index) => (
                            <div
                                key={index}
                                className={`relative rounded-2xl p-6 border-2 ${user.color} card-hover`}
                            >
                                {user.popular && (
                                    <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                    <span className="bg-green-500 text-white px-4 py-1 rounded-full text-sm font-semibold">
                      Most Popular
                    </span>
                                    </div>
                                )}
                                <div className="text-4xl mb-4">{user.icon}</div>
                                <h3 className="text-xl font-bold text-gray-900 mb-2">{user.type}</h3>
                                <p className="text-gray-600 mb-4">{user.description}</p>
                                <ul className="space-y-2 mb-6">
                                    {user.features.map((feature, idx) => (
                                        <li key={idx} className="flex items-start text-sm text-gray-700">
                                            <Shield className="w-4 h-4 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                                            {feature}
                                        </li>
                                    ))}
                                </ul>
                                <button className={`w-full ${user.buttonColor}`}>
                                    {user.buttonText}
                                </button>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Features Highlight */}
            <section className="py-20 bg-white">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="grid md:grid-cols-2 gap-12 items-center">
                        <div>
                            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-6">
                                Advanced Features for Modern Mobility
                            </h2>
                            <div className="space-y-6">
                                <div className="flex items-start">
                                    <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mr-4">
                                        <Shield className="w-6 h-6 text-blue-600" />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900">Multi-Factor Authentication</h3>
                                        <p className="text-gray-600">Secure access with userID/password, security questions, and Caesar cipher challenges</p>
                                    </div>
                                </div>
                                <div className="flex items-start">
                                    <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mr-4">
                                        <MessageCircle className="w-6 h-6 text-green-600" />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900">Virtual Assistant</h3>
                                        <p className="text-gray-600">24/7 AI-powered support for navigation, information, and guidance - available to all users including guests</p>
                                    </div>
                                </div>
                                <div className="flex items-start">
                                    <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mr-4">
                                        <Clock className="w-6 h-6 text-purple-600" />
                                    </div>
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900">Real-time Booking</h3>
                                        <p className="text-gray-600">Instant availability checking and seamless reservation system with notifications</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="bg-gradient-to-br from-blue-50 to-purple-50 rounded-2xl p-8">
                            <div className="text-center">
                                <div className="text-6xl mb-4">🚀</div>
                                <h3 className="text-2xl font-bold text-gray-900 mb-4">Ready to Get Started?</h3>
                                <p className="text-gray-600 mb-6">Join thousands of users who trust DALScooter for their daily commute</p>
                                <button onClick={handleGetStarted} className="btn-primary text-lg px-8 py-3">
                                    Start Your Journey Today
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Contact Section */}
            <section id="contact" className="py-20 gradient-bg">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
                            Get in Touch
                        </h2>
                        <p className="text-xl text-gray-600 max-w-2xl mx-auto">
                            Have questions? Our support team is here to help you 24/7
                        </p>
                    </div>

                    <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
                        <div className="text-center">
                            <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                <MessageCircle className="w-8 h-8 text-blue-600" />
                            </div>
                            <h3 className="text-lg font-semibold text-gray-900 mb-2">Support</h3>
                            <p className="text-gray-600 mb-2">support@dalscooter.com</p>
                            <p className="text-sm text-gray-500">24/7 Customer Support</p>
                        </div>
                        <div className="text-center">
                            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                <MapPin className="w-8 h-8 text-green-600" />
                            </div>
                            <h3 className="text-lg font-semibold text-gray-900 mb-2">Locations</h3>
                            <p className="text-gray-600 mb-2">Halifax, Nova Scotia</p>
                            <p className="text-sm text-gray-500">Multiple pickup points</p>
                        </div>
                        <div className="text-center">
                            <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                                <Users className="w-8 h-8 text-purple-600" />
                            </div>
                            <h3 className="text-lg font-semibold text-gray-900 mb-2">Franchise</h3>
                            <p className="text-gray-600 mb-2">franchise@dalscooter.com</p>
                            <p className="text-sm text-gray-500">Partner with us</p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="bg-gray-900 text-white py-12">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="grid md:grid-cols-4 gap-8">
                        <div>
                            <div className="flex items-center space-x-2 mb-4">
                                <div className="text-2xl">🛴</div>
                                <span className="text-xl font-bold">DALScooter</span>
                            </div>
                            <p className="text-gray-400 mb-4">
                                Premium electric scooter rentals for modern urban mobility.
                            </p>
                            <div className="text-sm text-gray-500">
                                © 2025 DALScooter. All rights reserved.
                            </div>
                        </div>
                        <div>
                            <h4 className="text-lg font-semibold mb-4">Services</h4>
                            <ul className="space-y-2 text-gray-400">
                                <li>eBike Rentals</li>
                                <li>Gyroscooter Rentals</li>
                                <li>Segway Rentals</li>
                                <li>Fleet Management</li>
                            </ul>
                        </div>
                        <div>
                            <h4 className="text-lg font-semibold mb-4">Support</h4>
                            <ul className="space-y-2 text-gray-400">
                                <li>Help Center</li>
                                <li>Safety Guidelines</li>
                                <li>Terms of Service</li>
                                <li>Privacy Policy</li>
                            </ul>
                        </div>
                        <div>
                            <h4 className="text-lg font-semibold mb-4">Connect</h4>
                            <ul className="space-y-2 text-gray-400">
                                <li>support@dalscooter.com</li>
                                <li>1-800-DAL-SCOOT</li>
                                <li>Halifax, Nova Scotia</li>
                                <li>Follow us on social media</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </footer>

            {/* Virtual Assistant for Guest Users */}
            <VirtualAssistant />
        </div>
    )
}

export default LandingPage