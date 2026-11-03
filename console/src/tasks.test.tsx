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

    // 组标题分列：assigned/running、done、failed、settled。
    expect(await screen.findByRole('heading', { name: /assigned \/ acked \/ running \(/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^done \(/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^failed \(/ })).toBeTruthy();
    expect(screen.getByRole('heading', { name: /^settled \(/ })).toBeTruthy();

    // done 任务：确认完成 + 驳回重跑；failed 任务：仅驳回重跑；
    // running 任务：无动作按钮；已确认任务：Confirmed 标记、无动作。
    expect(screen.getAllByText('Confirm done')).toHaveLength(1);
    expect(screen.getAllByText('Reject & rerun')).toHaveLength(2);
    expect(screen.getByText('Confirmed')).toBeTruthy();
    expect(screen.getByText(/task-3/)).toBeTruthy();
    // 无动作任务（running / confirmed）不渲染 Confirm/Reject 按钮：共
    // 1(done confirm) + 2(done+failed retry) 个任务动作。
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
    // done 组在前、failed 组在后；点击 failed 任务的驳回。
    fireEvent.click(retries[1]);
    expect(retrySpy).toHaveBeenCalledWith('net-1', 'task-2');
    // 提示须同时说清被驳回的原任务 id 与重跑的新代 id。
    expect(
      await screen.findByText(/Rejected task-2 .*rerun task-2-r1 dispatched/),
    ).toBeTruthy();
  });

  it('dispatches a command to a selected device via createTask', async () => {
    vi.spyOn(api.api, 'listTasks').mockResolvedValue([]);
    vi.spyOn(api.api, 'listDevices').mockResolvedValue([edge]);
    const createSpy = vi.spyOn(api.api, 'createTask').mockResolvedValue({ ...base, id: 'task-9' });
    render(<TasksSection networkId="net-1" />);

    // 选择目标设备（antd Select：打开下拉后点选项）。
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
