
import React from 'react';
import { useNavigate } from 'react-router-dom';
import './SystemOverview.css'; 

const PacketDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 200">
        {/* Modbus Packet */}
        <g transform="translate(50, 50)">
            <rect x="0" y="0" width="100" height="50" fill="#e0e7ff" stroke="#4f46e5" />
            <text x="50" y="30" fontSize="12" textAnchor="middle" fill="#4338ca">Transaction ID</text>
            
            <rect x="100" y="0" width="100" height="50" fill="#e0e7ff" stroke="#4f46e5" />
            <text x="150" y="30" fontSize="12" textAnchor="middle" fill="#4338ca">Protocol ID</text>

            <rect x="200" y="0" width="200" height="50" fill="#c7d2fe" stroke="#4f46e5" />
            <text x="300" y="30" fontSize="12" textAnchor="middle" fill="#4338ca">Function Code (Read)</text>

            <rect x="400" y="0" width="300" height="50" fill="#a5b4fc" stroke="#4f46e5" />
            <text x="550" y="30" fontSize="12" textAnchor="middle" fontWeight="bold" fill="#312e81">DATA Payload</text>
        </g>
        <text x="50" y="30" fontSize="14" fontWeight="bold" fill="#4f46e5">Modbus TCP/IP Frame</text>
    </svg>
);

export const ProtocolPage: React.FC = () => {
    const navigate = useNavigate();

    return (
        <div className="system-overview">
             <aside className="system-overview__sidebar">
                <div onClick={() => navigate('/')} style={{ cursor: 'pointer', marginBottom: '2rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: '#0d9488' }}>
                    ← Back to Dashboard
                </div>
                <h3 className="system-overview__nav-title">Protocols</h3>
                <nav>
                    <ul className="system-overview__nav-list">
                        <li className="system-overview__nav-item">
                            <a href="#modbus" className="system-overview__nav-link active">Modbus TCP/RTU</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#dnp3" className="system-overview__nav-link">DNP3</a>
                        </li>
                         <li className="system-overview__nav-item">
                            <a href="#iec61850" className="system-overview__nav-link">IEC 61850</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#tools" className="system-overview__nav-link">Analysis Tools</a>
                        </li>
                    </ul>
                </nav>
            </aside>

            <main className="system-overview__main">
                <div className="system-overview__header">
                    <h1 className="system-overview__title">Protocol Communication</h1>
                    <p className="system-overview__subtitle">
                        Industrial protocols are the language of OT. They prioritize availability and speed, often lacking built-in security features like encryption or authentication.
                    </p>
                </div>

                <div className="process-diagram">
                    <h4 style={{marginBottom: '1rem', color: '#475569'}}>Protocol Packet Structure</h4>
                    <PacketDiagram />
                </div>

                <section id="modbus" className="process-section">
                    <h2 className="process-section__title">Modbus TCP/RTU</h2>
                    <div className="process-section__content">
                        <p>
                            The de facto standard in industrial communication. Simple, robust, but inherently insecure.
                            <strong>Risk:</strong> No authentication means anyone on the network can issue 'Write' commands to PLCs.
                        </p>
                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">Port 502</span>
                                <div className="sensor-card__name">TCP Service</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">Function 5</span>
                                <div className="sensor-card__name">Write One Coil</div>
                            </div>
                        </div>
                    </div>
                </section>

                 <section id="dnp3" className="process-section">
                    <h2 className="process-section__title">DNP3 (Distributed Network Protocol)</h2>
                    <div className="process-section__content">
                        <p>
                            Widely used in Power and Water utilities for communication between SCADA and RTUs. 
                            Features time-stamping and event-oriented data, crucial for wide-area networks.
                            <strong>Secure Auth</strong> extension adds authentication challenges.
                        </p>
                    </div>
                </section>

                <section id="iec61850" className="process-section">
                    <h2 className="process-section__title">IEC 61850</h2>
                    <div className="process-section__content">
                        <p>
                            Standard for substation automation. Uses object-oriented data models and high-speed GOOSE messaging for protection relay tripping.
                        </p>
                    </div>
                </section>

                <section id="tools" className="process-section">
                    <h2 className="process-section__title">Analysis Tools</h2>
                    <div className="process-section__content">
                        <p>
                            Key tools for analyzing and securing these protocols:
                        </p>
                        <ul style={{marginTop: '1rem', marginLeft: '1.5rem'}}>
                            <li><strong>Wireshark:</strong> Deep packet inspection (Modbus, DNP3 dissectors).</li>
                            <li><strong>Scapy:</strong> Python library for packet manipulation and fuzzing.</li>
                            <li><strong>Zeek:</strong> Network security monitoring with industrial protocol analyzers.</li>
                        </ul>
                    </div>
                </section>

            </main>
        </div>
    );
};

export default ProtocolPage;
