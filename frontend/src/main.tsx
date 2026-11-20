import React from 'react'
import ReactDOM from 'react-dom/client'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './ui/theme.css'
import { applyTheme, currentTheme } from './ui/theme'
import App from './App'
import { ErrorBoundary } from './components/ErrorBoundary'

applyTheme(currentTheme())

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary what="REMN">
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
)
