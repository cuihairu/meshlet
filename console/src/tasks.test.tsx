import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { TasksSection } from './pages/devices/TasksSection';

const edge: api.Device = {
  id: 'dev-edge',
  network_id: 'net-1',
  name: 'edge',
  virtual_ipv4: '10.240.0.2',
  public_key: 'pk-edge',
  fingerprint: 'fp-edge',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  last_seen_at: null,
  online_state: 'online',
  presence_source: 'agent_report',
  dataplane_evidence: null,
  approved_at: '2026-01-01T00:00:00Z',
  direct_links: [],
  diagnostics: null,
  observed_endpoint: null,
  public_endpoint: null,
};

const base: api.Task = {
  id: 'task-1',
  network_id: 'net-1',
  target_device_id: 'dev-edge',
  cmd: 'echo hi',
  workdir: null,
  timeout_secs: null,
  state: 'done',
  retry_limit: 0,
  result_ref: 'task-1',
  exit_code: 0,
  log_tail: 'hi',
  confirmed_at: null,
  rejected_at: null,
  parent_task_id: null,
  created_at: 't',
  updated_at: 't',
};

const inflightTask: api.Task = { ...base, id: 'task-3', state: 'running', result_ref: null, exit_code: null, log_tail: null };
const doneTask: api.Task = { ...base, id: 'task-1', state: 'done', exit_code: 0 };
const failedTask: api.Task = { ...base, id: 'task-2', state: 'failed', exit_code: 1 };
const confirmedTask: api.Task = { ...base, id: 'task-4', state: 'done', confirmed_at: 't' };

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('TasksSection queue panel', () => {
  it('groups tasks by state and shows confirm/retry only where allowed', async () => {
    vi.spyOn(api.api, 'listTasks').mockResolvedValue([
      inflightTask,
      doneTask,
      failedTask,
      confirmedTask,
    ]);
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge]);
    render(<TasksSection networkId="net-1" />);

    // Separate group headings: assigned/acked/running, done, failed, settled.
    expect(await screen.findByRole('heading', { name: /assigned \/ acked \/ running \(/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^done \(/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^failed \(/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^settled \(/ })).toBeTruthy();

    // done tasks: Confirm done + Reject & rerun; failed tasks: Reject & rerun only;
    // running tasks: no action buttons; confirmed tasks: Confirmed marker, no actions.
    expect(screen.getAllByText('Confirm done')).toHaveLength(1);
    expect(screen.getAllByText('Reject & rerun')).toHaveLength(2);
    expect(screen.getByText('Confirmed')).toBeTruthy();
    expect(screen.getByText(/task-3/)).toBeTruthy();
    // Tasks with no actions (running / confirmed) render no Confirm/Reject buttons:
    // 1 (done confirm) + 2 (done+failed retry) task actions in total.
    expect(screen.queryAllByText('Confirm done')).toHaveLength(1);
  });

  it('confirm button calls confirmTask and shows notice', async () => {
    vi.spyOn(api.api, 'listTasks').mockResolvedValue([doneTask, inflightTask, confirmedTask]);
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge]);
    const confirmSpy = vi
      .spyOn(api.api, 'confirmTask')
      .mockResolvedValue({ ...doneTask, confirmed_at: 't' });
    render(<TasksSection networkId="net-1" />);

    fireEvent.click(await screen.findByText('Confirm done'));
    expect(confirmSpy).toHaveBeenCalledWith('net-1', 'task-1');
    expect(await screen.findByText(/Confirmed task-1/)).toBeTruthy();
  });

  it('retry button on a failed task calls retryTask and shows notice', async () => {
    vi.spyOn(api.api, 'listTasks').mockResolvedValue([doneTask, failedTask, inflightTask]);
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge]);
    const retrySpy = vi
      .spyOn(api.api, 'retryTask')
      .mockResolvedValue({ ...failedTask, id: 'task-2-r1', parent_task_id: 'task-2', state: 'assigned' });
    render(<TasksSection networkId="net-1" />);

    const retries = await screen.findAllByText('Reject & rerun');
    // The done group comes first and the failed group after; click the failed task's reject.
    fireEvent.click(retries[1]);
    expect(retrySpy).toHaveBeenCalledWith('net-1', 'task-2');
    // The notice must state both the rejected task id and the new rerun generation id.
    expect(
      await screen.findByText(/Rejected task-2 .*rerun task-2-r1 dispatched/),
    ).toBeTruthy();
  });

  it('dispatches a command to a selected device via createTask', async () => {
    vi.spyOn(api.api, 'listTasks').mockResolvedValue([]);
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge]);
    const createSpy = vi.spyOn(api.api, 'createTask').mockResolvedValue({ ...base, id: 'task-9' });
    render(<TasksSection networkId="net-1" />);

    // Select the target device (antd Select: open the dropdown, then click the option).
    fireEvent.mouseDown(await screen.findByRole('combobox'));
    fireEvent.click(await screen.findByText('edge (10.240.0.2)'));
    fireEvent.change(screen.getByPlaceholderText('Command to run on the device'), {
      target: { value: 'echo hello' },
    });
    fireEvent.click(screen.getByText('Dispatch'));

    expect(createSpy).toHaveBeenCalledWith('net-1', {
      target_device_id: 'dev-edge',
      cmd: 'echo hello',
    });
    expect(await screen.findByText(/Dispatched task-9/)).toBeTruthy();
  });
});
