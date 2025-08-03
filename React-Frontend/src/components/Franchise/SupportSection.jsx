import React, { useState } from 'react';
import CustomerList from './CustomerList';
import ConversationList from './ConversationList';
import ChatModal from './ChatModal';

export default function FranchiseSupportSection() {
  const [activeBookingId, setActiveBookingId] = useState(null);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-6">
      <CustomerList />
      <ConversationList onOpenChat={setActiveBookingId} />
      {activeBookingId && <ChatModal bookingId={activeBookingId} onClose={() => setActiveBookingId(null)} />}
    </div>
  );
}
