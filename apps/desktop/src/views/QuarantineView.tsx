import { useEffect, useState } from 'react';
import type { QuarantineDto } from '../api';
import { api } from '../api';

export function QuarantineView() {
  const [items, setItems] = useState<QuarantineDto[]>([]);
  useEffect(() => { void api.quarantinesList().then(setItems).catch(() => setItems([])); }, []);
  return <section className="card" aria-label="Quarantine"><p className="eyebrow">Safety boundary</p><h2>Quarantine</h2><div className="quarantine-list">{items.map((item, index) => <article key={`${item.fingerprint}-${index}`}><strong>{item.reasonCode}</strong><span className="mono">{item.fingerprint}</span><span>{item.sanitizedLocator}</span></article>)}{items.length === 0 && <p className="muted">No quarantined records.</p>}</div></section>;
}
