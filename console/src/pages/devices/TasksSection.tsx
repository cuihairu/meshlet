import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Button, Input, Select, Table, Tag } from 'antd';
import type { TableProps } from 'antd';
import { api, ApiError } from '../../api';
import type { Device, Task } from '../../api';
import { useLanguage } from '../../i18n/language-context';
import type { MessageKey } from '../../i18n/en';

/** MT-003 任务队列面板：assigned/running/done 分列 + 一键「确认完成/驳回重跑」。
 *
 * 确认是用户侧动作（agent 不得自判 done）——只有 done 任务给「确认完成」；
 * done/failed 给「驳回重跑」（服务端派发 `{root}-r{n}` 新一代）。已确认/
 * 已驳回的任务进 settled 区，不再给动作。
 */
export function TasksSection({
  networkId,
  onChanged,
  refreshKey = 0,
}: {
  networkId: string;
  onChanged?: () => void;
  refreshKey?: number;
}) {
  const [tasks, setTasks] = useState<Task[] | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [target, setTarget] = useState<string | undefined>(undefined);
  const [cmd, setCmd] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { t } = useLanguage();

  const load = useCallback(() => {
    api
      .listTasks(networkId)
      .then(setTasks)
      .catch((e) =>
        setError(
          t('tasks.loadError', { msg: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) }),
        ),
      );
    api.listDevices(networkId).then(setDevices).catch(() => setDevices([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [networkId]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const groups = useMemo(() => {
    const src = tasks ?? [];
    return {
      inFlight: src.filter((x) => ['assigned', 'acked', 'running'].includes(x.state)),
      done: src.filter((x) => x.state === 'done' && !x.confirmed_at && !x.rejected_at),
      failed: src.filter((x) => x.state === 'failed' && !x.rejected_at),
      settled: src.filter((x) => x.confirmed_at || x.rejected_at),
    };
  }, [tasks]);

  const fail = (prefix: MessageKey, e: unknown) =>
    setError(
      t(prefix, { msg: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) }),
    );

  const confirm = async (id: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.confirmTask(networkId, id);
      setNotice(t('tasks.confirmOk', { id: r.id }));
      load();
      onChanged?.();
    } catch (e) {
      fail('tasks.confirmError', e);
    } finally {
      setBusy(false);
    }
  };

  const retry = async (id: string) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.retryTask(networkId, id);
      setNotice(t('tasks.retryOk', { id, newId: r.id }));
      load();
      onChanged?.();
    } catch (e) {
      fail('tasks.retryError', e);
    } finally {
      setBusy(false);
    }
  };

  const dispatch = async () => {
    if (!target || !cmd.trim()) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await api.createTask(networkId, {
        target_device_id: target,
        cmd: cmd.trim(),
      });
      setNotice(t('tasks.dispatchOk', { id: r.id }));
      setCmd('');
      load();
      onChanged?.();
    } catch (e) {
      fail('tasks.dispatchError', e);
    } finally {
      setBusy(false);
    }
  };

  const deviceName = (id: string) => devices.find((d) => d.id === id)?.name ?? id;
  const activeDevices = devices.filter((d) => d.status === 'active');

  const columns: TableProps<Task>['columns'] = [
    {
      title: t('tasks.colId'),
      key: 'id',
      width: 170,
      render: (_, x) => <code>{x.id}</code>,
    },
    {
      title: t('tasks.colCmd'),
      key: 'cmd',
      render: (_, x) => (
        <span className="cell-ellipsis mono" title={x.cmd}>
          {x.cmd}
        </span>
      ),
    },
    {
      title: t('tasks.colTarget'),
      key: 'target',
      width: 140,
      render: (_, x) => deviceName(x.target_device_id),
    },
    {
      title: t('tasks.colResult'),
      key: 'result',
      render: (_, x) =>
        x.exit_code == null ? (
          <span className="muted">—</span>
        ) : (
          <Tag color={x.exit_code === 0 ? 'green' : 'red'} title={x.log_tail ?? undefined}>
            exit {x.exit_code}
          </Tag>
        ),
    },
  ];

  const group = (
    title: string,
    rows: Task[],
    actions?: (x: Task) => ReactNode,
    emptyHint: string = t('tasks.none'),
  ) => (
    <div className="task-group" key={title}>
      <h3>
        {title} <span className="muted">({rows.length})</span>
      </h3>
      {rows.length === 0 ? (
        <p className="muted">{emptyHint}</p>
      ) : (
        <Table<Task>
          rowKey="id"
          columns={[
            ...columns,
            ...(actions
              ? [
                  {
                    title: '',
                    key: 'actions',
                    render: actions,
                  } satisfies NonNullable<TableProps<Task>['columns']>[number],
                ]
              : []),
          ]}
          dataSource={rows}
          size="small"
          pagination={false}
        />
      )}
    </div>
  );

  return (
    <div>
      <h2>{t('tasks.title')}</h2>
      <p className="muted">{t('tasks.dispatchHint')}</p>
      <div className="task-dispatch">
        <Select
          style={{ minWidth: 220 }}
          placeholder={t('tasks.dispatchTarget')}
          value={target}
          onChange={setTarget}
          options={activeDevices.map((d) => ({ value: d.id, label: `${d.name} (${d.virtual_ipv4})` }))}
        />
        <Input
          style={{ flex: 1 }}
          placeholder={t('tasks.dispatchCmd')}
          value={cmd}
          onChange={(e) => setCmd(e.target.value)}
          onPressEnter={dispatch}
        />
        <Button type="primary" onClick={dispatch} loading={busy} disabled={!target || !cmd.trim()}>
          {t('tasks.dispatch')}
        </Button>
      </div>
      {notice && <p className="muted">{notice}</p>}
      {error && <p className="error">{error}</p>}
      {group(t('tasks.inFlight'), groups.inFlight)}
      {group(
        t('tasks.done'),
        groups.done,
        (x) => (
          <>
            <Button size="small" type="primary" loading={busy} onClick={() => confirm(x.id)}>
              {t('tasks.confirm')}
            </Button>{' '}
            <Button size="small" danger loading={busy} onClick={() => retry(x.id)}>
              {t('tasks.retry')}
            </Button>
          </>
        ),
      )}
      {group(
        t('tasks.failed'),
        groups.failed,
        (x) => (
          <Button size="small" danger loading={busy} onClick={() => retry(x.id)}>
            {t('tasks.retry')}
          </Button>
        ),
      )}
      {group(
        t('tasks.settled'),
        groups.settled,
        (x) =>
          x.confirmed_at ? (
            <Tag color="green">{t('tasks.confirmDone')}</Tag>
          ) : (
            <Tag color="orange">{t('tasks.rejected')}</Tag>
          ),
      )}
    </div>
  );
}
