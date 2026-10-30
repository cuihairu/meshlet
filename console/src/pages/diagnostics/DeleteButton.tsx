import { Button, Popconfirm } from 'antd';
import { useLanguage } from '../../i18n/language-context';

/** Two-step delete confirm (antd Popconfirm) — shared by the publish tables. */
export function DeleteButton({
  busy,
  onDelete,
}: {
  busy: boolean;
  onDelete: () => Promise<void>;
}) {
  const { t } = useLanguage();
  return (
    <Popconfirm
      title={t('delete.title')}
      okText={t('delete.confirm')}
      cancelText={t('delete.cancel')}
      disabled={busy}
      onConfirm={() => {
        onDelete().catch(() => {});
      }}
    >
      <Button size="small" type="link" danger>
        {t('delete.label')}
      </Button>
    </Popconfirm>
  );
}
