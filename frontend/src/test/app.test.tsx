/**
 * Frontend tests covering user-visible behavior.
 *
 * Tests:
 * 1. Login page renders and submits demo login
 * 2. LoginPage shows error on failed API call
 * 3. Layout renders nav items and logout for authenticated user
 * 4. Dashboard shows empty state when no snapshots
 * 5. Dashboard shows seeding button for operator role
 * 6. SnapshotsPage renders snapshot table from API data
 * 7. DiffPage shows empty state when no diff selected
 * 8. MLPage benchmark tab renders metrics from API
 * 9. AuditPage renders audit entries with action filters
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { AuthProvider, useAuth } from '../context/AuthContext';
import LoginPage from '../components/LoginPage';
import Layout from '../components/Layout';
import Dashboard from '../components/Dashboard';
import SnapshotsPage from '../components/SnapshotsPage';
import DiffPage from '../components/DiffPage';
import MLPage from '../components/MLPage';
import AuditPage from '../components/AuditPage';

// ─── Mock API with vi.hoisted for shared mock functions ──────────────────────

const mockApi = vi.hoisted(() => ({
  loginDemo: vi.fn(),
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok' }),
  listSnapshots: vi.fn().mockResolvedValue([]),
  getSnapshot: vi.fn(),
  createSnapshot: vi.fn(),
  deleteSnapshot: vi.fn(),
  seedSampleSnapshots: vi.fn(),
  computeDiff: vi.fn(),
  getDiff: vi.fn(),
  evaluateDiff: vi.fn(),
  getMLBenchmark: vi.fn().mockResolvedValue({
    dataset_size: 32,
    model_metrics: {
      accuracy: 0.875,
      macro_f1: 0.82,
      weighted_f1: 0.87,
      macro_precision: 0.84,
      macro_recall: 0.80,
      total_samples: 32,
      confusion_matrix: {},
      per_class: {
        LOW: { precision: 0.9, recall: 0.9, f1: 0.9, support: 10 },
        MEDIUM: { precision: 0.85, recall: 0.80, f1: 0.82, support: 9 },
        HIGH: { precision: 0.82, recall: 0.78, f1: 0.80, support: 7 },
        CRITICAL: { precision: 0.87, recall: 0.85, f1: 0.86, support: 6 },
      },
    },
    baseline_metrics: { accuracy: 0.5, macro_f1: 0.38 },
    improvements: { accuracy_delta: 0.375, f1_delta: 0.44 },
    failure_cases: ['Ambiguous MEDIUM/HIGH boundary for mixed port exposure'],
    data_provenance: 'Synthetic labeled dataset based on canonical exposure patterns',
    evaluation_command: 'python3 backend/app/ml/evaluate.py',
  }),
  generateAdvisory: vi.fn(),
  listAuditLogs: vi.fn().mockResolvedValue([]),
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock('../services/api', () => ({
  __esModule: true,
  ...mockApi,
}));

// ─── Helpers ─────────────────────────────────────────────────────────────────

function renderWithAuth(
  ui: React.ReactElement,
  authPatch?: Partial<{ token: string; role: string; username: string; isAuthenticated: boolean }>
) {
  const Wrapper = ({ children }: { children: React.ReactNode }) => {
    return <AuthProvider>{children}</AuthProvider>;
  };
  if (authPatch?.isAuthenticated) {
    const AuthedWrapper = ({ children }: { children: React.ReactNode }) => {
      return (
        <AuthProvider>
          <AuthSetter token={authPatch.token ?? 'test-token'} role={authPatch.role ?? 'operator'} username={authPatch.username ?? 'test-user'}>
            {children}
          </AuthSetter>
        </AuthProvider>
      );
    };
    return render(ui, { wrapper: AuthedWrapper });
  }
  return render(ui, { wrapper: Wrapper });
}

function AuthSetter({ token, role, username, children }: { token: string; role: string; username: string; children: React.ReactNode }) {
  const { setAuth } = useAuth();
  React.useEffect(() => {
    setAuth({ token, role: role as 'viewer' | 'operator' | 'admin', username, isAuthenticated: true });
  }, []);
  return <>{children}</>;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('LoginPage', () => {
  it('renders demo login form with role selector', () => {
    renderWithAuth(<LoginPage />);
    expect(screen.getByText(/Multi-Cloud Inventory Diff/i)).toBeInTheDocument();
    expect(screen.getByText(/Local Demo Mode/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Sign In/i })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Operator/i })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Viewer/i })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Admin/i })).toBeInTheDocument();
  });

  it('calls loginDemo and updates auth on successful submit', async () => {
    mockApi.loginDemo.mockResolvedValueOnce({
      token: 'tok-123',
      role: 'operator',
      username: 'alice',
      isAuthenticated: true,
    });
    renderWithAuth(<LoginPage />);
    const btn = screen.getByRole('button', { name: /Sign In/i });
    fireEvent.click(btn);
    await waitFor(() => expect(mockApi.loginDemo).toHaveBeenCalledWith({ role: 'operator', username: 'demo-user' }));
  });

  it('shows error banner on login failure', async () => {
    mockApi.loginDemo.mockRejectedValueOnce(new Error('Invalid credentials'));
    renderWithAuth(<LoginPage />);
    fireEvent.click(screen.getByRole('button', { name: /Sign In/i }));
    await waitFor(() => expect(screen.getByText(/Invalid credentials/i)).toBeInTheDocument());
  });
});

describe('Layout', () => {
  it('renders navigation items and user info for authenticated operator', () => {
    renderWithAuth(
      <Layout currentPage="dashboard" onNavigate={vi.fn()}>
        <div>content</div>
      </Layout>,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'bob' }
    );
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Snapshots')).toBeInTheDocument();
    expect(screen.getByText('Diff Inspector')).toBeInTheDocument();
    expect(screen.getByText('ML Evaluation')).toBeInTheDocument();
    // operator can see Audit Log
    expect(screen.getByText('Audit Log')).toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Sign Out/i })).toBeInTheDocument();
  });

  it('navigates when nav item clicked', () => {
    const onNavigate = vi.fn();
    renderWithAuth(
      <Layout currentPage="dashboard" onNavigate={onNavigate}>
        <div>content</div>
      </Layout>,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'bob' }
    );
    fireEvent.click(screen.getByText('Snapshots'));
    expect(onNavigate).toHaveBeenCalledWith('snapshots');
  });
});

describe('Dashboard', () => {
  it('shows empty state when no snapshots returned', async () => {
    mockApi.listSnapshots.mockResolvedValueOnce([]);
    mockApi.getMLBenchmark.mockResolvedValueOnce({
      dataset_size: 32,
      model_metrics: { accuracy: 0.875, macro_f1: 0.82, weighted_f1: 0.87, macro_precision: 0.84, macro_recall: 0.80, total_samples: 32, confusion_matrix: {}, per_class: {} },
      baseline_metrics: { accuracy: 0.5, macro_f1: 0.38 },
      improvements: { accuracy_delta: 0.375, f1_delta: 0.44 },
      failure_cases: [],
      data_provenance: 'test',
      evaluation_command: 'python3 test',
    });
    renderWithAuth(
      <Dashboard onNavigateToDiff={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByText(/No snapshots found/i)).toBeInTheDocument());
  });

  it('shows seed button for operator role', async () => {
    mockApi.listSnapshots.mockResolvedValueOnce([]);
    renderWithAuth(
      <Dashboard onNavigateToDiff={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByRole('button', { name: /Load Sample Data/i })).toBeInTheDocument());
  });

  it('shows ML benchmark metrics on dashboard', async () => {
    mockApi.listSnapshots.mockResolvedValueOnce([]);
    renderWithAuth(
      <Dashboard onNavigateToDiff={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByText(/87.5%/)).toBeInTheDocument());
  });
});

describe('SnapshotsPage', () => {
  it('renders snapshot table with loaded snapshots', async () => {
    mockApi.listSnapshots.mockResolvedValueOnce([
      {
        id: 'snap-1',
        name: 'Baseline AWS',
        cloud_provider: 'aws',
        source_type: 'config-export',
        asset_count: 5,
        description: 'Test snapshot',
        created_by: 'alice',
        created_at: new Date().toISOString(),
      },
    ]);
    renderWithAuth(
      <SnapshotsPage onNavigateToDiff={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByText('Baseline AWS')).toBeInTheDocument());
    expect(screen.getByText('AWS')).toBeInTheDocument();
  });

  it('shows empty state when no snapshots exist', async () => {
    mockApi.listSnapshots.mockResolvedValueOnce([]);
    renderWithAuth(
      <SnapshotsPage onNavigateToDiff={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByText(/No snapshots yet/i)).toBeInTheDocument());
  });
});

describe('DiffPage', () => {
  it('shows empty state when no diff selected', async () => {
    mockApi.listSnapshots.mockResolvedValueOnce([]);
    renderWithAuth(
      <DiffPage selectedDiffId={null} onNavigateToML={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByText(/No diff selected/i)).toBeInTheDocument());
  });

  it('loads and displays diff data when selectedDiffId provided', async () => {
    mockApi.getDiff.mockResolvedValueOnce({
      id: 'diff-1',
      base_snapshot_id: 'snap-base',
      target_snapshot_id: 'snap-target',
      added_count: 2,
      removed_count: 1,
      modified_count: 3,
      items: [],
      exposure_summary: { total_changes: 6, exposure_escalated: 2, iam_escalated: 1, public_added: 1 },
      owner_grouping: [],
      created_by: 'alice',
      created_at: new Date().toISOString(),
    });
    renderWithAuth(
      <DiffPage selectedDiffId="diff-1" onNavigateToML={vi.fn()} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => {
      expect(screen.getByText('2')).toBeInTheDocument();
    });
  });
});

describe('MLPage', () => {
  it('renders benchmark tab with per-class metrics', async () => {
    renderWithAuth(
      <MLPage selectedDiffId={null} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    const benchTab = await screen.findByRole('button', { name: /Offline Benchmark/i });
    fireEvent.click(benchTab);
    await waitFor(() => expect(screen.getByText(/87.5%/i)).toBeInTheDocument());
  });

  it('shows failure cases in benchmark tab', async () => {
    renderWithAuth(
      <MLPage selectedDiffId={null} />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    const benchTab = await screen.findByRole('button', { name: /Offline Benchmark/i });
    fireEvent.click(benchTab);
    await waitFor(() => expect(screen.getByText(/Ambiguous MEDIUM\/HIGH boundary/i)).toBeInTheDocument());
  });
});

describe('AuditPage', () => {
  it('shows empty state when no audit entries', async () => {
    mockApi.listAuditLogs.mockResolvedValueOnce([]);
    renderWithAuth(
      <AuditPage />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    await waitFor(() => expect(screen.getByText(/No audit entries/i)).toBeInTheDocument());
  });

  it('renders audit entries with actions and actors', async () => {
    mockApi.listAuditLogs.mockResolvedValueOnce([
      {
        id: 'audit-1',
        actor: 'alice',
        role: 'operator',
        action: 'COMPUTE_DIFF',
        resource_type: 'diff',
        resource_id: 'diff-1',
        details: { total_changes: 5 },
        created_at: new Date().toISOString(),
      },
    ]);
    renderWithAuth(
      <AuditPage />,
      { isAuthenticated: true, token: 'tok', role: 'operator', username: 'alice' }
    );
    // Wait for the audit entry's action badge (not the select option)
    await waitFor(() => {
      const badges = screen.getAllByText('COMPUTE_DIFF');
      expect(badges.length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('alice')).toBeInTheDocument();
    });
  });
});