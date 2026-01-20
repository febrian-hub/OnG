import { createRoot } from 'react-dom/client';
import { App } from '@app/index';
import './index.css';

// Import the main page component
import AppContent from './App';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Root element not found');
}

createRoot(rootElement).render(
  <App>
    <AppContent />
  </App>
);
