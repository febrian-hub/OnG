
import React from 'react';
import { useNavigate } from 'react-router-dom';
import './SystemOverview.css'; // Reusing layout styles

const PurdueDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 600">
        <defs>
            <linearGradient id="enterpriseGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f0fdf4" />
                <stop offset="100%" stopColor="#dcfce7" />
            </linearGradient>
             <linearGradient id="dmzGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#fff7ed" />
                <stop offset="100%" stopColor="#ffedd5" />
            </linearGradient>
             <linearGradient id="controlGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#eff6ff" />
                <stop offset="100%" stopColor="#dbeafe" />
            </linearGradient>
        </defs>

        {/* Level 4/5: Enterprise */}
        <rect x="50" y="20" width="700" height="100" rx="10" fill="url(#enterpriseGrad)" stroke="#16a34a" strokeWidth="2" />
        <text x="70" y="50" fontSize="16" fontWeight="bold" fill="#15803d">Level 4/5: Enterprise Network</text>
        <rect x="200" y="40" width="100" height="60" fill="white" stroke="#16a34a" rx="5" />
        <text x="250" y="75" fontSize="12" textAnchor="middle">ERP / SAP</text>
        <rect x="400" y="40" width="100" height="60" fill="white" stroke="#16a34a" rx="5" />
        <text x="450" y="75" fontSize="12" textAnchor="middle">Email / Web</text>

         {/* Firewall */}
         <rect x="350" y="130" width="100" height="30" fill="#dc2626" rx="5" />
         <text x="400" y="150" fontSize="12" textAnchor="middle" fill="white" fontWeight="bold">Enterprise FW</text>
         <line x1="400" y1="120" x2="400" y2="130" stroke="#94a3b8" strokeWidth="2" />
         <line x1="400" y1="160" x2="400" y2="180" stroke="#94a3b8" strokeWidth="2" />

        {/* Level 3.5: DMZ */}
        <rect x="50" y="180" width="700" height="120" rx="10" fill="url(#dmzGrad)" stroke="#ea580c" strokeWidth="2" />
        <text x="70" y="210" fontSize="16" fontWeight="bold" fill="#c2410c">Level 3.5: Industrial DMZ</text>
        <rect x="150" y="220" width="120" height="60" fill="white" stroke="#ea580c" rx="5" />
        <text x="210" y="255" fontSize="12" textAnchor="middle">Historian Mirror</text>
        <rect x="550" y="220" width="120" height="60" fill="white" stroke="#ea580c" rx="5" />
        <text x="610" y="255" fontSize="12" textAnchor="middle">Remote Access</text>

        {/* Firewall */}
         <rect x="350" y="310" width="100" height="30" fill="#dc2626" rx="5" />
         <text x="400" y="330" fontSize="12" textAnchor="middle" fill="white" fontWeight="bold">Industrial FW</text>
         <line x1="400" y1="300" x2="400" y2="310" stroke="#94a3b8" strokeWidth="2" />
         <line x1="400" y1="340" x2="400" y2="360" stroke="#94a3b8" strokeWidth="2" />

        {/* Level 0-3: OT Network */}
        <rect x="50" y="360" width="700" height="220" rx="10" fill="url(#controlGrad)" stroke="#2563eb" strokeWidth="2" />
        <text x="70" y="390" fontSize="16" fontWeight="bold" fill="#1d4ed8">Level 0-3: Industrial Control System (ICS)</text>
        
        {/* Level 3 */}
        <text x="100" y="420" fontSize="14" fontWeight="bold" fill="#64748b">L3: Operations</text>
        <rect x="250" y="400" width="100" height="50" fill="white" stroke="#2563eb" rx="5" />
        <text x="300" y="430" fontSize="12" textAnchor="middle">SCADA Server</text>
        <rect x="450" y="400" width="100" height="50" fill="white" stroke="#2563eb" rx="5" />
        <text x="500" y="430" fontSize="12" textAnchor="middle">Historian</text>

        {/* Level 1-2 */}
        <text x="100" y="480" fontSize="14" fontWeight="bold" fill="#64748b">L2/L1: Control</text>
        <rect x="200" y="470" width="80" height="40" fill="white" stroke="#2563eb" rx="5" />
        <text x="240" y="495" fontSize="12" textAnchor="middle">HMI</text>
        <rect x="350" y="470" width="80" height="40" fill="white" stroke="#2563eb" rx="5" />
        <text x="390" y="495" fontSize="12" textAnchor="middle">PLC</text>
        <rect x="500" y="470" width="80" height="40" fill="white" stroke="#2563eb" rx="5" />
        <text x="540" y="495" fontSize="12" textAnchor="middle">RTU</text>

        {/* Level 0 */}
        <text x="100" y="540" fontSize="14" fontWeight="bold" fill="#64748b">L0: Field</text>
        <circle cx="390" cy="550" r="15" fill="#e2e8f0" stroke="#64748b" />
        <text x="390" y="554" fontSize="10" textAnchor="middle">Mot</text>
        <line x1="390" y1="510" x2="390" y2="535" stroke="#64748b" strokeWidth="2" />
    </svg>
);

export const PurduePage: React.FC = () => {
    const navigate = useNavigate();

    return (
        <div className="system-overview">
             <aside className="system-overview__sidebar">
                <div onClick={() => navigate('/')} style={{ cursor: 'pointer', marginBottom: '2rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: '#0d9488' }}>
                    ← Back to Dashboard
                </div>
                <h3 className="system-overview__nav-title">Architecture Layers</h3>
                <nav>
                    <ul className="system-overview__nav-list">
                        <li className="system-overview__nav-item">
                            <a href="#enterprise" className="system-overview__nav-link">Level 4/5: Enterprise</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#dmz" className="system-overview__nav-link">Level 3.5: DMZ</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#operations" className="system-overview__nav-link">Level 3: Operations</a>
                        </li>
                         <li className="system-overview__nav-item">
                            <a href="#control" className="system-overview__nav-link">Level 1/2: Control</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#field" className="system-overview__nav-link">Level 0: Physical</a>
                        </li>
                    </ul>
                </nav>
            </aside>

            <main className="system-overview__main">
                <div className="system-overview__header">
                    <h1 className="system-overview__title">Purdue Reference Model</h1>
                    <p className="system-overview__subtitle">
                        The industry standard for segmenting Industrial Control Systems (ICS) from Enterprise networks.
                        Proper segmentation is the first line of defense against cyber threats.
                    </p>
                </div>

                <div className="process-diagram">
                    <h4 style={{marginBottom: '1rem', color: '#475569'}}>Architecture Telemetry</h4>
                    <PurdueDiagram />
                </div>

                <section id="enterprise" className="process-section">
                    <h2 className="process-section__title">Level 4/5: Enterprise Zone</h2>
                    <div className="process-section__content">
                        <p>
                            Business Logistics and Enterprise networks. This is where ERP, email, and corporate web services reside.
                            It should be strictly separated from the operational network.
                        </p>
                    </div>
                </section>

                <section id="dmz" className="process-section">
                    <h2 className="process-section__title">Level 3.5: Industrial DMZ</h2>
                    <div className="process-section__content">
                        <p>
                            The Demilitarized Zone (DMZ) acts as a buffer between IT and OT. 
                            Services like Historian Mirrors, Patch Management, and Remote Access Gateways are hosted here.
                            Direct communication between L4 and L3 should generally be blocked; they should terminate in the DMZ.
                        </p>
                    </div>
                </section>

                <section id="operations" className="process-section">
                    <h2 className="process-section__title">Level 3: Operations</h2>
                    <div className="process-section__content">
                        <p>
                            Site-wide supervisory control. SCADA servers, Master Historians, and Engineering Workstations (EWS) manage the overall production process.
                        </p>
                    </div>
                </section>

                 <section id="control" className="process-section">
                    <h2 className="process-section__title">Level 1/2: Control & Basic Control</h2>
                    <div className="process-section__content">
                        <p>
                            <strong>Level 2:</strong> HMIs and local supervisory systems.<br/>
                            <strong>Level 1:</strong> Intelligent devices like PLCs, RTUs, and Dedicated Controllers that execute logic.
                        </p>
                    </div>
                </section>
                
                 <section id="field" className="process-section">
                    <h2 className="process-section__title">Level 0: Physical Process</h2>
                    <div className="process-section__content">
                        <p>
                            The actual physical sensors (PT, TT, Flow Meters) and actuators (Valves, Pumps, Motors) that interact with the physical world.
                        </p>
                    </div>
                </section>
            </main>
        </div>
    );
};

export default PurduePage;
