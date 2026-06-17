import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Suppress benign ResizeObserver errors that bubble up from flexible containers or React Flow resize loops
if (typeof window !== 'undefined') {
  const isResizeObserverError = (msg: any): boolean => {
    if (!msg) return false;
    if (typeof msg !== 'string') return false;
    const lower = msg.toLowerCase();
    return lower.includes('resizeobserver') || lower.includes('resize observer');
  };

  window.addEventListener('error', (e) => {
    if (isResizeObserverError(e.message)) {
      e.stopImmediatePropagation();
      e.stopPropagation();
      e.preventDefault();
    }
  });

  window.addEventListener('unhandledrejection', (e) => {
    const msg = e.reason?.message || e.reason || '';
    if (isResizeObserverError(msg)) {
      e.stopImmediatePropagation();
      e.stopPropagation();
      e.preventDefault();
    }
  });
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
