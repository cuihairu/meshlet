import { useState } from 'react';

/** Two-step inline delete confirm — shared by the publish tables. */
export function DeleteButton({
  busy,
  onDelete,
}: {
  busy: boolean;
  onDelete: () => Promise<void>;
}) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return (
      <button type="button" className="link" onClick={() => setConfirming(true)}>
        Delete
      </button>
    );
  }
  return (
    <>
      <button
        type="button"
        className="danger"
        disabled={busy}
        onClick={() => {
          onDelete().then(() => setConfirming(false));
        }}
      >
        Confirm delete
      </button>{' '}
      <button type="button" className="link" onClick={() => setConfirming(false)}>
        Cancel
      </button>
    </>
  );
}
