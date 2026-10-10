import { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import LoginPage from './components/LoginPage';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import SnapshotsPage from './components/SnapshotsPage';
import DiffPage from './components/DiffPage';
import MLPage from './components/MLPage';
import AuditPage from './components/AuditPage';

export type PageId = 'dashboard' | 'snapshots' | 'diff' | 'ml' | 'audit';

function AppInner() {
  const { isAuthenticated } = useAuth();
  const [page, setPage] = useState<PageId>('dashboard');
  const [selectedDiffId, setSelectedDiffId] = useState<string | null>(null);

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const navigateToDiff = (diffId: string) => {
    setSelectedDiffId(diffId);
    setPage('diff');
  };

  const navigateToML = (diffId: string) => {
    setSelectedDiffId(diffId);
    setPage('ml');
  };

  return (
    <Layout currentPage={page} onNavigate={setPage}>
      {page === 'dashboard' && (
        <Dashboard onNavigateToDiff={navigateToDiff} />
      )}
      {page === 'snapshots' && (
        <SnapshotsPage onNavigateToDiff={navigateToDiff} />
      )}
      {page === 'diff' && (
        <DiffPage selectedDiffId={selectedDiffId} onNavigateToML={navigateToML} />
      )}
      {page === 'ml' && (
        <MLPage selectedDiffId={selectedDiffId} />
      )}
      {page === 'audit' && <AuditPage />}
    </Layout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}