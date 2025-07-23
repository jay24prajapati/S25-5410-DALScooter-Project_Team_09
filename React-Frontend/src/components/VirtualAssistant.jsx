import React, { useState, useRef, useEffect } from 'react'
import { MessageCircle, X, Send, Bot, User, HelpCircle } from 'lucide-react'

const VirtualAssistant = () => {
    const [isOpen, setIsOpen] = useState(false)
    const [messages, setMessages] = useState([
        {
            id: 1,
            type: 'bot',
            content: "Hi! I'm DALBot, your virtual assistant. I can help you navigate our site and answer questions about our scooter rental service. How can I help you today?",
            timestamp: new Date()
        }
    ])
    const [inputMessage, setInputMessage] = useState('')
    const [isTyping, setIsTyping] = useState(false)
    const messagesEndRef = useRef(null)

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
    }

    useEffect(() => {
        scrollToBottom()
    }, [messages])

    // Predefined responses for guest navigation
    const getBotResponse = (userMessage) => {
        const message = userMessage.toLowerCase().trim()

        // Navigation help
        if (message.includes('register') || message.includes('sign up') || message.includes('create account')) {
            return "To register, click the 'Get Started' button in the navigation bar or hero section. You'll need to provide an email, password, and choose between Customer or Franchise account."
        }

        if (message.includes('login') || message.includes('sign in')) {
            return "To login, click 'Get Started' and then use your existing credentials. Our system uses 3-factor authentication: password, security question, and Caesar cipher challenge."
        }

        // Bike information
        if (message.includes('bike') || message.includes('scooter') || message.includes('price') || message.includes('cost')) {
            return "We offer 3 types of vehicles:\n🚲 eBikes: $15/hour - Eco-friendly with pedal assist\n🛴 Gyroscooters: $20/hour - Self-balancing technology\n🛵 Segways: $25/hour - Premium personal transporters\n\nScroll down to see detailed information about each type!"
        }

        if (message.includes('ebike') || message.includes('e-bike')) {
            return "eBikes are our eco-friendly electric bicycles with pedal assist technology. They cost $15/hour and feature long battery life. Perfect for eco-conscious riders!"
        }

        if (message.includes('gyroscooter') || message.includes('gyro')) {
            return "Gyroscooters are self-balancing electric scooters that cost $20/hour. They feature smart control technology and provide a stable, smooth ride experience."
        }

        if (message.includes('segway')) {
            return "Segways are our premium personal transporters at $25/hour. They offer the highest safety features, comfort, and long-range capabilities."
        }

        // Availability
        if (message.includes('available') || message.includes('availability')) {
            return "Current availability:\n🚲 eBikes: 8 available\n🛴 Gyroscooters: 12 available\n🛵 Segways: 4 available\n\nTo check real-time availability for specific dates, please register for an account."
        }

        // Booking process
        if (message.includes('book') || message.includes('reserve') || message.includes('rent')) {
            return "To book a scooter, you need to:\n1. Register for an account\n2. Complete email verification\n3. Login with 3-factor authentication\n4. Select your preferred scooter type\n5. Choose date and duration\n\nGuests can only browse - booking requires registration."
        }

        // Feedback and reviews
        if (message.includes('feedback') || message.includes('review') || message.includes('rating')) {
            return "You can view customer feedback and ratings for each scooter type in the bike showcase section below. Customer reviews help you choose the best option for your needs!"
        }

        // User types
        if (message.includes('customer') || message.includes('user type')) {
            return "We have 3 user types:\n👤 Guests: Browse and get info (no registration needed)\n🔐 Customers: Full booking access with secure authentication\n👑 Franchise: Business management and fleet control\n\nScroll down to learn more about each type!"
        }

        if (message.includes('franchise')) {
            return "Franchise operators can manage bike inventory, set pricing, handle bookings, and view analytics. They get admin access with advanced dashboard features."
        }

        // Location and contact
        if (message.includes('location') || message.includes('where') || message.includes('halifax')) {
            return "We're located in Halifax, Nova Scotia with multiple pickup points including:\n📍 Downtown Halifax\n📍 Dalhousie University\n📍 Halifax Waterfront\n📍 Spring Garden Road\n📍 Halifax Shopping Centre"
        }

        if (message.includes('contact') || message.includes('support') || message.includes('help')) {
            return "Contact us:\n📧 support@dalscooter.com\n📧 franchise@dalscooter.com\n📞 1-800-DAL-SCOOT\n\nWe offer 24/7 customer support!"
        }

        // Navigation help
        if (message.includes('navigate') || message.includes('navigation') || message.includes('menu')) {
            return "Use the navigation menu to:\n• View our bike fleet (Bikes section)\n• Learn about features\n• Check pricing details\n• Contact information\n\nOr scroll down to explore all sections!"
        }

        // Features
        if (message.includes('feature') || message.includes('security') || message.includes('authentication')) {
            return "Our key features include:\n🔒 Multi-factor authentication\n🤖 24/7 virtual assistant (that's me!)\n⏰ Real-time booking system\n📱 Mobile-friendly design\n🔔 Instant notifications\n📊 Analytics for franchise operators"
        }

        // Greetings
        if (message.includes('hello') || message.includes('hi') || message.includes('hey')) {
            return "Hello! Welcome to DALScooter! I'm here to help you navigate our platform. Ask me about our bikes, how to register, pricing, or anything else you'd like to know!"
        }

        if (message.includes('thanks') || message.includes('thank you')) {
            return "You're welcome! Is there anything else I can help you with today? I'm here to make your DALScooter experience as smooth as possible! 😊"
        }

        // Default response with suggestions
        return "I'd be happy to help! Here are some things you can ask me about:\n\n• 'How do I register?' - Account creation\n• 'What bikes do you have?' - Vehicle types & pricing\n• 'How much does it cost?' - Pricing information\n• 'Where are you located?' - Pickup locations\n• 'How do I book?' - Booking process\n• 'Contact information' - Support details\n\nWhat would you like to know?"
    }

    const handleSendMessage = () => {
        if (!inputMessage.trim()) return

        const userMessage = {
            id: Date.now(),
            type: 'user',
            content: inputMessage,
            timestamp: new Date()
        }

        setMessages(prev => [...prev, userMessage])
        setInputMessage('')
        setIsTyping(true)

        // Simulate bot thinking time
        setTimeout(() => {
            const botResponse = {
                id: Date.now() + 1,
                type: 'bot',
                content: getBotResponse(inputMessage),
                timestamp: new Date()
            }
            setMessages(prev => [...prev, botResponse])
            setIsTyping(false)
        }, 1000 + Math.random() * 1000) // 1-2 seconds delay
    }

    const handleKeyPress = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault()
            handleSendMessage()
        }
    }

    const quickQuestions = [
        "How do I register?",
        "What bikes do you have?",
        "How much does it cost?",
        "Where are you located?",
        "How do I book a scooter?"
    ]

    const handleQuickQuestion = (question) => {
        setInputMessage(question)
        setTimeout(() => handleSendMessage(), 100)
    }

    return (
        <>
            {/* Chat Button */}
            <div className="fixed bottom-6 right-6 z-50">
                <button
                    onClick={() => setIsOpen(!isOpen)}
                    className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white p-4 rounded-full shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-110"
                >
                    {isOpen ? <X size={24} /> : <MessageCircle size={24} />}
                </button>
            </div>

            {/* Chat Window */}
            {isOpen && (
                <div className="fixed bottom-24 right-6 w-96 max-w-[calc(100vw-3rem)] h-[500px] bg-white rounded-lg shadow-2xl border border-gray-200 z-50 flex flex-col">
                    {/* Header */}
                    <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-4 rounded-t-lg flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                            <Bot className="w-6 h-6" />
                            <div>
                                <h3 className="font-semibold">DALBot Assistant</h3>
                                <p className="text-xs opacity-90">Guest Navigation Helper</p>
                            </div>
                        </div>
                        <button
                            onClick={() => setIsOpen(false)}
                            className="text-white hover:text-gray-200 transition-colors"
                        >
                            <X size={20} />
                        </button>
                    </div>

                    {/* Messages */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4">
                        {messages.map((message) => (
                            <div
                                key={message.id}
                                className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
                            >
                                <div
                                    className={`max-w-[80%] p-3 rounded-lg ${
                                        message.type === 'user'
                                            ? 'bg-blue-600 text-white rounded-br-none'
                                            : 'bg-gray-100 text-gray-800 rounded-bl-none'
                                    }`}
                                >
                                    <div className="flex items-start space-x-2">
                                        {message.type === 'bot' && <Bot className="w-4 h-4 mt-0.5 text-blue-600" />}
                                        {message.type === 'user' && <User className="w-4 h-4 mt-0.5" />}
                                        <div className="flex-1">
                                            <p className="text-sm whitespace-pre-line">{message.content}</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}

                        {isTyping && (
                            <div className="flex justify-start">
                                <div className="bg-gray-100 text-gray-800 p-3 rounded-lg rounded-bl-none max-w-[80%]">
                                    <div className="flex items-center space-x-2">
                                        <Bot className="w-4 h-4 text-blue-600" />
                                        <div className="flex space-x-1">
                                            <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                                            <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                                            <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Quick Questions */}
                    {messages.length <= 1 && (
                        <div className="p-4 border-t border-gray-200">
                            <p className="text-xs text-gray-600 mb-2 flex items-center">
                                <HelpCircle className="w-3 h-3 mr-1" />
                                Quick questions:
                            </p>
                            <div className="space-y-1">
                                {quickQuestions.slice(0, 3).map((question, index) => (
                                    <button
                                        key={index}
                                        onClick={() => handleQuickQuestion(question)}
                                        className="text-xs text-blue-600 hover:text-blue-700 block w-full text-left p-1 hover:bg-blue-50 rounded transition-colors"
                                    >
                                        {question}
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Input */}
                    <div className="p-4 border-t border-gray-200">
                        <div className="flex space-x-2">
                            <input
                                type="text"
                                value={inputMessage}
                                onChange={(e) => setInputMessage(e.target.value)}
                                onKeyPress={handleKeyPress}
                                placeholder="Ask me anything about DALScooter..."
                                className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                                disabled={isTyping}
                            />
                            <button
                                onClick={handleSendMessage}
                                disabled={!inputMessage.trim() || isTyping}
                                className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white p-2 rounded-lg transition-colors"
                            >
                                <Send size={16} />
                            </button>
                        </div>
                        <p className="text-xs text-gray-500 mt-1">
                            Press Enter to send • Available 24/7 for guest navigation
                        </p>
                    </div>
                </div>
            )}
        </>
    )
}

export default VirtualAssistant