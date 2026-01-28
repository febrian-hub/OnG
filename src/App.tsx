/**
 * Root Application Component
 * 
 * This is the main entry point wrapped by providers in main.tsx
 */

import { Routes, Route } from 'react-router-dom';
import { Dashboard } from './components/Dashboard';
import { SystemOverviewPage } from './pages/SystemOverviewPage';
import { PurduePage } from './pages/PurduePage';
import { ProtocolPage } from './pages/ProtocolPage';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/system-overview" element={<SystemOverviewPage />} />
      <Route path="/purdue-architecture" element={<PurduePage />} />
      <Route path="/protocol-communication" element={<ProtocolPage />} />
    </Routes>
  );
}

export default App;

