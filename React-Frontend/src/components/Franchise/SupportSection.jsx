import React from 'react';

export default function SupportSection({
  tickets,
  selectedTicket,
  setSelectedTicket,
  showChat,
  setShowChat
}) {
  return (
    <div className="space-y-6">
      <h3 className="text-2xl font-bold text-blue-800">Customer Support</h3>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Support Tickets Panel */}
        <div className="bg-white rounded-xl shadow-lg border border-blue-100">
          <div className="p-6 border-b border-blue-100">
            <h4 className="text-lg font-semibold text-blue-700">Support Tickets</h4>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {tickets.map(ticket => (
              <div
                key={ticket.id}
                className="p-4 border-b border-blue-50 hover:bg-blue-50 cursor-pointer"
                onClick={() => {
                  setSelectedTicket(ticket);
                  setShowChat(true);
                }}
              >
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <p className="font-semibold text-blue-800">#{ticket.id}</p>
                    <p className="text-sm text-gray-600">{ticket.customer}</p>
                  </div>
                  <div className="text-right">
                    <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                      ticket.priority === 'High'
                        ? 'bg-red-100 text-red-800'
                        : ticket.priority === 'Medium'
                        ? 'bg-orange-100 text-orange-800'
                        : 'bg-green-100 text-green-800'
                    }`}>
                      {ticket.priority}
                    </span>
                    <p className="text-xs text-gray-500 mt-1">{ticket.timestamp}</p>
                  </div>
                </div>
                <p className="text-gray-700 text-sm mb-2">{ticket.issue}</p>
                <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                  ticket.status === 'Open'
                    ? 'bg-red-100 text-red-800'
                    : ticket.status === 'In Progress'
                    ? 'bg-orange-100 text-orange-800'
                    : 'bg-green-100 text-green-800'
                }`}>
                  {ticket.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Virtual Assistant */}
        <div className="bg-white rounded-xl shadow-lg border border-blue-100">
          <div className="p-6 border-b border-blue-100">
            <h4 className="text-lg font-semibold text-blue-700">Virtual Assistant</h4>
          </div>
          <div className="p-6">
            <div className="bg-blue-50 rounded-lg p-4 mb-4">
              <p className="text-blue-800 font-semibold mb-2">🤖 DAL Assistant</p>
              <p className="text-blue-700 text-sm">Hello! I can help you with:</p>
              <ul className="text-blue-600 text-sm mt-2 space-y-1">
                <li>• Site navigation</li>
                <li>• Booking reference lookups</li>
                <li>• Bike information</li>
                <li>• Customer communication</li>
              </ul>
            </div>
            <div className="flex space-x-2">
              <input
                type="text"
                placeholder="Ask me anything..."
                className="flex-1 p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
              />
              <button className="bg-blue-500 text-white px-4 py-3 rounded-lg hover:bg-blue-600 transition-colors">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Chat Modal */}
      {showChat && selectedTicket && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl w-full max-w-2xl mx-4 h-3/4 flex flex-col">
            {/* Chat Header */}
            <div className="p-6 border-b border-blue-100">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-xl font-bold text-blue-800">Support Chat - #{selectedTicket.id}</h3>
                  <p className="text-blue-600">{selectedTicket.customer}</p>
                </div>
                <button
                  onClick={() => setShowChat(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Chat Body */}
            <div className="flex-1 p-6 overflow-y-auto">
              <div className="space-y-4">
                <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg">
                  <p className="text-red-800 font-semibold">Issue: {selectedTicket.issue}</p>
                  <p className="text-red-600 text-sm mt-1">{selectedTicket.timestamp}</p>
                </div>
                <div className="bg-blue-50 border-l-4 border-blue-400 p-4 rounded-r-lg ml-8">
                  <p className="text-blue-800">Thank you for contacting us. We're looking into your issue.</p>
                  <p className="text-blue-600 text-sm mt-1">Franchise Support</p>
                </div>
              </div>
            </div>

            {/* Chat Input */}
            <div className="p-6 border-t border-blue-100">
              <div className="flex space-x-4">
                <input
                  type="text"
                  placeholder="Type your response..."
                  className="flex-1 p-3 border-2 border-blue-200 rounded-lg focus:border-blue-500 focus:outline-none"
                />
                <button className="bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 transition-colors font-semibold">
                  Send
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
