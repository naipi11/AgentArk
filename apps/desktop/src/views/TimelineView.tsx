import type { PublicSessionDetail } from '../api';
import { VirtualTimeline } from '../components/VirtualTimeline';

export function TimelineView({ session }: { session: PublicSessionDetail | null }) {
  if (!session) return <section className="card"><p className="muted">Select a session to inspect its timeline.</p></section>;
  return <section className="card" aria-label="Session timeline"><p className="eyebrow">Timeline</p><h2>{session.title ?? 'Untitled session'}</h2><VirtualTimeline messages={session.messages} toolEvents={session.toolEvents} /></section>;
}
