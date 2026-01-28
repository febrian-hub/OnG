/**
 * Dashboard Component
 * 
 * Main dashboard container with feature cards grid
 */

import { useNavigate } from 'react-router-dom';
import { FeatureCard } from './FeatureCard';
import { ProfileSidebar } from '../Sidebar';
import './Dashboard.css';

// SVG Icons
const MonitorIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
    <line x1="8" y1="21" x2="16" y2="21" />
    <line x1="12" y1="17" x2="12" y2="21" />
  </svg>
);

const NetworkIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
    <rect x="9" y="9" width="6" height="6" />
    <line x1="9" y1="2" x2="9" y2="4" />
    <line x1="15" y1="2" x2="15" y2="4" />
    <line x1="9" y1="20" x2="9" y2="22" />
    <line x1="15" y1="20" x2="15" y2="22" />
    <line x1="20" y1="9" x2="22" y2="9" />
    <line x1="20" y1="15" x2="22" y2="15" />
    <line x1="2" y1="9" x2="4" y2="9" />
    <line x1="2" y1="15" x2="4" y2="15" />
  </svg>
);

const ProtocolIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="16 18 22 12 16 6" />
    <polyline points="8 6 2 12 8 18" />
  </svg>
);

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();

  const handleLaunchSystemOverview = () => {
    navigate('/system-overview');
  };

  const handleLaunchPurdue = () => {
    navigate('/purdue-architecture');
  };

  const handleLaunchProtocol = () => {
    navigate('/protocol-communication');
  };

  return (
    <div className="dashboard-layout">
      <ProfileSidebar />
      
      <div className="dashboard">
        <header className="dashboard__header">
          <h1 className="dashboard__title">Based Knowledge</h1>
          <p className="dashboard__subtitle">Bridging OT and IT for secure industrial infrastructures</p>
        </header>

        <div className="dashboard__grid">
          {/* System Overview Card */}
          <FeatureCard
            icon={<MonitorIcon />}
            iconBgClass="feature-card__icon--teal"
            label="REAL-TIME MONITORING"
            title="System Overview"
            description="Operational dashboard for real-time monitoring of all sensors and equipment across the oil & gas processing facilities."
            features={[
              { color: '#0d9488', text: '27 Field Sensors' },
              { color: '#0891b2', text: 'Live Data Monitoring' },
              { color: '#0e7490', text: 'Trend Charts & Analytics' }
            ]}
            onLaunch={handleLaunchSystemOverview}
          />

          {/* Purdue Architecture Card */}
          <FeatureCard
            icon={<NetworkIcon />}
            iconBgClass="feature-card__icon--yellow"
            label="ICS NETWORK SECURITY"
            title="Purdue Architecture"
            description="Visualization of the Industrial Control System architecture based on the Purdue Reference Model (ISA-95/IEC 62443)."
            features={[
              { color: '#ca8a04', text: '6 Purdue Levels' },
              { color: '#eab308', text: 'Security Zones' },
              { color: '#facc15', text: 'Network Segmentation' }
            ]}
            onLaunch={handleLaunchPurdue}
          />

          {/* Protocol Communication Card */}
          <FeatureCard
            icon={<ProtocolIcon />}
            iconBgClass="feature-card__icon--purple"
            label="INDUSTRIAL PROTOCOLS"
            title="Protocol Communication"
            description="Interactive learning and analysis regarding industrial protocols (Modbus, DNP3, OPC UA)."
            features={[
              { color: '#7c3aed', text: 'Protocol Simulators' },
              { color: '#8b5cf6', text: 'Packet Analysis' },
              { color: '#a78bfa', text: 'Security Checkups' }
            ]}
            onLaunch={handleLaunchProtocol}
          />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

