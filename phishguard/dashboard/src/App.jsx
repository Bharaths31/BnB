import React, { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:8000/api/events')
      .then(res => res.json())
      .then(data => {
        setEvents(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Error fetching events:", err);
        setLoading(false);
      });
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8 font-sans">
      <header className="mb-8">
        <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
          PhishGuard Security Dashboard
        </h1>
        <p className="text-gray-400 mt-2">Real-time local email intelligence</p>
      </header>

      <main>
        {loading ? (
          <div className="flex justify-center items-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
          </div>
        ) : (
          <div className="grid gap-6">
            {events.length === 0 ? (
              <div className="p-6 bg-gray-800 rounded-lg text-center text-gray-500">
                No recent events found.
              </div>
            ) : (
              events.map((ev, idx) => (
                <div key={idx} className="bg-gray-800 rounded-lg shadow-lg overflow-hidden border border-gray-700 transition-all hover:border-gray-500">
                  <div className="p-6">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h3 className="text-xl font-semibold mb-1">{ev.subject || '(No Subject)'}</h3>
                        <p className="text-sm text-gray-400">From: {ev.sender}</p>
                        <p className="text-xs text-gray-500">{new Date(ev.received_at).toLocaleString()}</p>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${ev.verdict === 'BLOCK' ? 'bg-red-900 text-red-300' : ev.verdict === 'FLAG' ? 'bg-yellow-900 text-yellow-300' : 'bg-green-900 text-green-300'}`}>
                        {ev.verdict}
                      </span>
                    </div>
                    
                    <div className="mt-4 pt-4 border-t border-gray-700">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-sm text-gray-400">Threat Score</span>
                        <span className="text-sm font-mono">{ev.score.toFixed(2)}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div 
                          className={`h-2 rounded-full ${ev.score > 0.85 ? 'bg-red-500' : ev.score > 0.5 ? 'bg-yellow-500' : 'bg-green-500'}`} 
                          style={{width: `${Math.min(ev.score * 100, 100)}%`}}
                        ></div>
                      </div>
                    </div>
                    
                    {ev.reasons && ev.reasons.length > 0 && (
                      <div className="mt-4">
                        <h4 className="text-sm font-semibold mb-2 text-gray-300">Detection Reasons:</h4>
                        <ul className="list-disc list-inside text-sm text-gray-400">
                          {ev.reasons.map((r, i) => <li key={i}>{r}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
