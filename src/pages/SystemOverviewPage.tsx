import React from 'react';
import { useNavigate } from 'react-router-dom';
import './SystemOverview.css';

// Diagram Components (Inline SVGs for now)
const WellheadDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 300">
        {/* Ground Line */}
        <line x1="50" y1="200" x2="750" y2="200" stroke="#94a3b8" strokeWidth="2" />
        
        {/* Wellhead Structure */}
        <rect x="100" y="150" width="60" height="50" fill="#cbd5e1" stroke="#475569" />
        <rect x="110" y="100" width="40" height="50" fill="#94a3b8" stroke="#475569" />
        
        {/* Christmas Tree Valves */}
        <path d="M120 90 L140 90 L130 110 Z" fill="#ef4444" /> {/* Swab Valve */}
        <path d="M140 130 L160 110 L160 150 Z" fill="#ef4444" /> {/* Wing Valve */}
        
        {/* Flowline */}
        <path d="M160 130 L300 130 Q350 130 350 180 L350 200" fill="none" stroke="#22c55e" strokeWidth="4" />
        
        {/* Flow Line Text */}
        <text x="220" y="120" fontSize="14" fill="#15803d">Flowline (Oil + Gas + Water)</text>
        
        {/* Sensors */}
        <circle cx="200" cy="130" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="200" y="134" fontSize="10" textAnchor="middle" fontWeight="bold">PT</text>
        
        <circle cx="250" cy="130" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="250" y="134" fontSize="10" textAnchor="middle" fontWeight="bold">TT</text>
    </svg>
);

const SeparationDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 300">
        <defs>
            <linearGradient id="oilGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#818cf8" stopOpacity="0.2" />
                <stop offset="50%" stopColor="#fbbf24" />
                <stop offset="100%" stopColor="#22c55e" />
            </linearGradient>
        </defs>
        
        {/* Separator Vessel */}
        <path d="M150 100 L650 100 Q700 100 700 150 Q700 200 650 200 L150 200 Q100 200 100 150 Q100 100 150 100Z" 
              fill="url(#oilGradient)" stroke="#475569" strokeWidth="2" />
        
        {/* Inlet */}
        <path d="M20 130 L100 130" stroke="#cbd5e1" strokeWidth="4" />
        <path d="M110 120 L110 160" stroke="#475569" strokeWidth="4" /> {/* Diverter */}

        {/* Outlets */}
        <path d="M400 100 L400 50" stroke="#818cf8" strokeWidth="4" /> {/* Gas */}
        <text x="410" y="70" fontSize="12" fill="#6366f1">Gas Outlet</text>

        <path d="M680 140 L750 140" stroke="#fbbf24" strokeWidth="4" /> {/* Oil */}
        <text x="710" y="130" fontSize="12" fill="#d97706">Oil Outlet</text>

        <path d="M500 200 L500 250" stroke="#22c55e" strokeWidth="4" /> {/* Water */}
        <text x="510" y="240" fontSize="12" fill="#15803d">Water Outlet</text>

        {/* Internals */}
        <line x1="600" y1="150" x2="600" y2="200" stroke="#475569" strokeWidth="2" strokeDasharray="4 2" /> {/* Weir */}
        
        {/* Sensors */}
        <circle cx="200" cy="80" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="200" y="84" fontSize="10" textAnchor="middle" fontWeight="bold">PT</text>
        
        <circle cx="550" cy="80" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="550" y="84" fontSize="10" textAnchor="middle" fontWeight="bold">LT</text>
    </svg>
);

const CompressionDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 300">
        {/* Scrubber */}
        <rect x="100" y="100" width="60" height="120" rx="10" fill="#e2e8f0" stroke="#475569" strokeWidth="2" />
        <text x="130" y="240" fontSize="12" textAnchor="middle">Scrubber</text>

        {/* Compressor */}
        <path d="M250 130 L350 110 L350 210 L250 190 Z" fill="#cbd5e1" stroke="#475569" strokeWidth="2" />
        <text x="300" y="165" fontSize="12" textAnchor="middle" fontWeight="bold">Compressor</text>

        {/* Cooler */}
        <rect x="450" y="120" width="100" height="80" fill="#bae6fd" stroke="#0ea5e9" strokeWidth="2" />
        <path d="M460 130 L540 130 M460 150 L540 150 M460 170 L540 170" stroke="#0ea5e9" strokeWidth="2" />
        <text x="500" y="220" fontSize="12" textAnchor="middle">Air Cooler</text>

        {/* Piping */}
        <path d="M50 160 L100 160" stroke="#64748b" strokeWidth="3" />
        <path d="M160 160 L250 160" stroke="#64748b" strokeWidth="3" />
        <path d="M350 160 L450 160" stroke="#64748b" strokeWidth="3" />
        <path d="M550 160 L650 160" stroke="#64748b" strokeWidth="3" />

        {/* Sensors */}
        <circle cx="200" cy="140" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="200" y="144" fontSize="10" textAnchor="middle" fontWeight="bold">PT</text>
        <circle cx="400" cy="140" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="400" y="144" fontSize="10" textAnchor="middle" fontWeight="bold">TT</text>
    </svg>
);

const OilTreatmentDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 300">
        {/* Heater Treater */}
        <rect x="150" y="80" width="200" height="140" rx="10" fill="#fef3c7" stroke="#d97706" strokeWidth="2" />
        <text x="250" y="150" fontSize="14" textAnchor="middle" fill="#92400e">Heater Treater</text>
        
        {/* Electrostatic Grids */}
        <line x1="170" y1="110" x2="330" y2="110" stroke="#d97706" strokeWidth="1" strokeDasharray="5 5" />
        <line x1="170" y1="130" x2="330" y2="130" stroke="#d97706" strokeWidth="1" strokeDasharray="5 5" />

        {/* Pump */}
        <circle cx="500" cy="200" r="30" fill="#cbd5e1" stroke="#475569" strokeWidth="2" />
        <path d="M500 170 L500 200 L530 200" fill="none" stroke="#475569" strokeWidth="2" />
        <text x="500" y="250" fontSize="12" textAnchor="middle">Export Pump</text>

        {/* Piping */}
        <path d="M50 150 L150 150" stroke="#64748b" strokeWidth="3" />
        <path d="M350 200 L470 200" stroke="#64748b" strokeWidth="3" />
        <path d="M530 200 L650 200" stroke="#64748b" strokeWidth="3" />

        {/* Sensors */}
        <circle cx="400" cy="180" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="400" y="184" fontSize="10" textAnchor="middle" fontWeight="bold">BS&W</text>
    </svg>
);

const ProducedWaterDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 300">
        {/* Hydrocyclone */}
        <path d="M200 100 L300 100 L250 250 Z" fill="#cffafe" stroke="#0891b2" strokeWidth="2" />
        <text x="250" y="150" fontSize="12" textAnchor="middle" fill="#155e75">Hydrocyclone</text>

        {/* Degasser */}
        <rect x="450" y="100" width="100" height="150" fill="#ecfeff" stroke="#06b6d4" strokeWidth="2" />
        <text x="500" y="180" fontSize="12" textAnchor="middle">Degasser</text>

        {/* Piping */}
        <path d="M100 120 L220 120" stroke="#64748b" strokeWidth="3" />
        <path d="M250 250 L250 280 L400 280 L400 180 L450 180" stroke="#64748b" strokeWidth="3" />
        <path d="M250 100 L250 50 L600 50" stroke="#64748b" strokeWidth="3" /> {/* Oil reject */}
        <text x="300" y="40" fontSize="10" fill="#64748b">Oil Reject</text>

        <path d="M550 180 L650 180" stroke="#64748b" strokeWidth="3" /> {/* Water out */}
        
        {/* Sensors */}
        <circle cx="600" cy="160" r="10" fill="white" stroke="#0f172a" strokeWidth="2" />
        <text x="600" y="164" fontSize="8" textAnchor="middle" fontWeight="bold">OIW</text>
    </svg>
);

const UtilityDiagram = () => (
    <svg className="process-diagram__svg" viewBox="0 0 800 300">
        {/* Generator */}
        <rect x="150" y="100" width="120" height="80" fill="#f1f5f9" stroke="#475569" strokeWidth="2" />
        <text x="210" y="145" fontSize="12" textAnchor="middle">Gas Turbine Gen</text>
        
        {/* Switchgear */}
        <rect x="350" y="80" width="100" height="120" fill="#e2e8f0" stroke="#475569" strokeWidth="2" />
        <text x="400" y="145" fontSize="12" textAnchor="middle">MCC / Switchgear</text>

        {/* Control Room */}
        <rect x="550" y="80" width="150" height="100" fill="#f0f9ff" stroke="#0284c7" strokeWidth="2" />
        <text x="625" y="135" fontSize="14" textAnchor="middle" fontWeight="bold" fill="#0369a1">Control Room</text>

        {/* Connections */}
        <line x1="270" y1="140" x2="350" y2="140" stroke="#f59e0b" strokeWidth="2" />
        <line x1="450" y1="140" x2="550" y2="140" stroke="#3b82f6" strokeWidth="2" strokeDasharray="4 2" />
    </svg>
);

export const SystemOverviewPage: React.FC = () => {
    const navigate = useNavigate();

    return (
        <div className="system-overview">
            <aside className="system-overview__sidebar">
                <div onClick={() => navigate('/')} style={{ cursor: 'pointer', marginBottom: '2rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: '#0d9488' }}>
                    ← Back to Dashboard
                </div>
                <h3 className="system-overview__nav-title">Process Modules</h3>
                <nav>
                    <ul className="system-overview__nav-list">
                        <li className="system-overview__nav-item">
                            <a href="#wellhead" className="system-overview__nav-link active">1. Wellhead & Gathering</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#separation" className="system-overview__nav-link">2. Separation System</a>
                        </li>
                         <li className="system-overview__nav-item">
                            <a href="#compression" className="system-overview__nav-link">3. Gas Compression</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#oil-treatment" className="system-overview__nav-link">4. Oil Treatment</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#produced-water" className="system-overview__nav-link">5. Produced Water</a>
                        </li>
                        <li className="system-overview__nav-item">
                            <a href="#utilities" className="system-overview__nav-link">6. Utility & Safety</a>
                        </li>
                    </ul>
                </nav>
            </aside>

            <main className="system-overview__main">
                <div className="system-overview__header">
                    <h1 className="system-overview__title">System Overview</h1>
                    <p className="system-overview__subtitle">
                        Comprehensive guide to the Upstream Oil & Gas production process, covering the journey from reservoir to export.
                        Understanding these systems is crucial for designing secure OT infrastructures.
                    </p>
                </div>

                {/* Section 1: Wellhead */}
                <section id="wellhead" className="process-section">
                    <h2 className="process-section__title">
                        <span style={{color: '#64748b'}}>01.</span> Wellhead & Gathering
                    </h2>
                    
                    <div className="process-section__content">
                        <p>
                            The <strong>Wellhead</strong> acts as the primary interface between the reservoir and the surface facilities. 
                            Topped by the <strong>Christmas Tree</strong>, it provides pressure containment and flow control via a series of safety valves (Master, Wing, Swab).
                        </p>
                        
                        <div className="process-diagram">
                            <h4 style={{marginBottom: '1rem', color: '#475569'}}>Christmas Tree & Flowline Architecture</h4>
                            <WellheadDiagram />
                        </div>

                        <p>
                            Fluids from individual wells flow through the <strong>Flowlines</strong> to a central <strong>Gathering Manifold</strong>. 
                            The flow is typically multiphase (Oil, Gas, Water, Sand) and highly turbulent.
                        </p>

                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">PT-101</span>
                                <div className="sensor-card__name">Wellhead Pressure</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">TT-101</span>
                                <div className="sensor-card__name">Flowline Temp</div>
                            </div>
                             <div className="sensor-card">
                                <span className="sensor-card__code">WHCP</span>
                                <div className="sensor-card__name">Wellhead Control Panel</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">SSV</span>
                                <div className="sensor-card__name">Surface Safety Valve</div>
                            </div>
                        </div>
                    </div>
                </section>
                

                {/* Section 2: Separation */}
                <section id="separation" className="process-section">
                    <h2 className="process-section__title">
                        <span style={{color: '#64748b'}}>02.</span> Separation System
                    </h2>
                    <div className="process-section__content">
                        <p>
                            The multiphase stream enters the <strong>3-Phase Separator</strong> where it is separated into Gas, Oil, and Water based on density differences.
                            Internal components like <strong>Weirs</strong> and <strong>Demisters</strong> enhance separation efficiency.
                        </p>
                        <div className="process-diagram">
                            <h4 style={{marginBottom: '1rem', color: '#475569'}}>3-Phase Separation Process</h4>
                            <SeparationDiagram />
                        </div>
                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">LT-201</span>
                                <div className="sensor-card__name">Interface Level</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">PT-201</span>
                                <div className="sensor-card__name">Vessel Pressure</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">LCV</span>
                                <div className="sensor-card__name">Level Control Valve</div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Section 3: Compression */}
                <section id="compression" className="process-section">
                    <h2 className="process-section__title">
                        <span style={{color: '#64748b'}}>03.</span> Gas Compression
                    </h2>
                    <div className="process-section__content">
                        <p>
                            Separated gas is compressed to high pressure for export. 
                            <strong>Scrubbers</strong> remove remaining liquids to protect the compressor, while <strong>Coolers</strong> manage discharge temperature.
                        </p>
                        <div className="process-diagram">
                            <h4 style={{marginBottom: '1rem', color: '#475569'}}>Gas Compression Train</h4>
                            <CompressionDiagram />
                        </div>
                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">PT-301</span>
                                <div className="sensor-card__name">Suction Pressure</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">TT-301</span>
                                <div className="sensor-card__name">Discharge Temp</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">VIB</span>
                                <div className="sensor-card__name">Vibration Monitor</div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Section 4: Oil Treatment */}
                <section id="oil-treatment" className="process-section">
                    <h2 className="process-section__title">
                        <span style={{color: '#64748b'}}>04.</span> Oil Treatment
                    </h2>
                    <div className="process-section__content">
                        <p>
                            Crude oil often contains emulsified water. 
                            <strong>Heater Treaters</strong> and <strong>Electrostatic Coalescers</strong> break these emulsions to ensure the oil meets export specifications (BS&W).
                        </p>
                        <div className="process-diagram">
                            <h4 style={{marginBottom: '1rem', color: '#475569'}}>Dehydration & Export</h4>
                            <OilTreatmentDiagram />
                        </div>
                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">AT-401</span>
                                <div className="sensor-card__name">BS&W Analyzer</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">FT-401</span>
                                <div className="sensor-card__name">Fiscal Metering</div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Section 5: Produced Water */}
                <section id="produced-water" className="process-section">
                    <h2 className="process-section__title">
                        <span style={{color: '#64748b'}}>05.</span> Produced Water
                    </h2>
                    <div className="process-section__content">
                        <p>
                            Water separated from the process contains oil droplets. 
                            <strong>Hydrocyclones</strong> use centrifugal force to remove oil down to ppm levels before the water is safely disposed of or reinjected.
                        </p>
                        <div className="process-diagram">
                            <h4 style={{marginBottom: '1rem', color: '#475569'}}>Water Treatment System</h4>
                            <ProducedWaterDiagram />
                        </div>
                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">AT-501</span>
                                <div className="sensor-card__name">Oil-in-Water Analyzer</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">FT-501</span>
                                <div className="sensor-card__name">Disposal Flow</div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Section 6: Utilities */}
                <section id="utilities" className="process-section">
                    <h2 className="process-section__title">
                        <span style={{color: '#64748b'}}>06.</span> Utility & Safety
                    </h2>
                    <div className="process-section__content">
                        <p>
                            Essential support systems include <strong>Power Generation</strong>, <strong>Instrument Air</strong>, and the <strong>Fire & Gas System</strong> which monitors the facility for hazards.
                        </p>
                        <div className="process-diagram">
                            <h4 style={{marginBottom: '1rem', color: '#475569'}}>Plant Utilities</h4>
                            <UtilityDiagram />
                        </div>
                        <div className="sensor-grid">
                            <div className="sensor-card">
                                <span className="sensor-card__code">F&G</span>
                                <div className="sensor-card__name">Fire & Gas Detectors</div>
                            </div>
                            <div className="sensor-card">
                                <span className="sensor-card__code">ESD</span>
                                <div className="sensor-card__name">Emergency Shutdown</div>
                            </div>
                        </div>
                    </div>
                </section>
            </main>
        </div>
    );
};

export default SystemOverviewPage;
