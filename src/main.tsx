import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// Auto-recover if Vite encounters a stale chunk during Vercel deployment switch
window.addEventListener('vite:preloadError', (event) => {
  console.warn('[ThreatLens] Stale chunk detected during deployment switch. Refreshing...', event);
  window.location.reload();
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
