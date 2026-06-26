import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import App from './App';
import '@fontsource/inter/400.css';
import '@fontsource/inter/600.css';
import './index.css';

// PhishSkill-aligned theme: blue/emerald/rose/slate palette
const theme = createTheme({
  palette: {
    mode: 'light',
    primary: { main: '#2563EB' },
    error: { main: '#E11D48' },
    success: { main: '#059669' },
    background: { default: '#F8FAFC', paper: '#FFFFFF' },
    text: { primary: '#0F172A', secondary: '#475569' },
  },
  typography: {
    fontFamily: 'Inter, system-ui, sans-serif',
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
  },
  components: {
    MuiButton: {
      styleOverrides: { root: { textTransform: 'none', borderRadius: 8 } },
    },
    MuiChip: {
      styleOverrides: { root: { borderRadius: 6 } },
    },
  },
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </ThemeProvider>
  </React.StrictMode>
);
