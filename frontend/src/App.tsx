import { Routes, Route, Navigate } from 'react-router-dom';
import QueuePage from './pages/QueuePage';
import DetailPage from './pages/DetailPage';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/queue" replace />} />
      <Route path="/queue" element={<QueuePage />} />
      <Route path="/queue/:id" element={<DetailPage />} />
    </Routes>
  );
}
