import { useEffect, useMemo, useRef, useState } from 'react';
import type { PublicMessage, PublicToolEvent } from '../api';

type TimelineRow =
  | { kind: 'message'; ordinal: number; role: string; text: string }
  | { kind: 'tool'; ordinal: number; role: string; text: string };

type Props = {
  messages: PublicMessage[];
  toolEvents: PublicToolEvent[];
  height?: number;
};

const ROW_HEIGHT = 72;
const OVERSCAN = 10;

export function VirtualTimeline({ messages, toolEvents, height = 560 }: Props) {
  const rows = useMemo<TimelineRow[]>(
    () => [
      ...messages.map((message) => ({
        kind: 'message' as const,
        ordinal: message.ordinal,
        role: message.role,
        text: message.text,
      })),
      ...toolEvents.map((event) => ({
        kind: 'tool' as const,
        ordinal: event.ordinal,
        role: event.toolName,
        text: [event.visibleInput, event.visibleOutput].filter(Boolean).join('\n'),
      })),
    ].sort((left, right) => left.ordinal - right.ordinal),
    [messages, toolEvents],
  );
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + height) / ROW_HEIGHT) + OVERSCAN);
  const visible = rows.slice(first, last);

  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return;
    const onScroll = () => setScrollTop(node.scrollTop);
    node.addEventListener('scroll', onScroll, { passive: true });
    return () => node.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <div className="timeline" ref={scrollRef} style={{ height }} aria-label="Timeline">
      <div style={{ height: rows.length * ROW_HEIGHT, position: 'relative' }}>
        {visible.map((row, index) => (
          <article
            className="timeline-row"
            data-timeline-row
            key={`${row.kind}-${row.ordinal}`}
            style={{ top: (first + index) * ROW_HEIGHT, height: ROW_HEIGHT }}
          >
            <span className="timeline-role">{row.role}</span>
            <span className="timeline-text">{row.text}</span>
          </article>
        ))}
      </div>
    </div>
  );
}
