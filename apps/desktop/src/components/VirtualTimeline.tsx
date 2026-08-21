import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { PublicMessage, PublicToolEvent } from '../api';
import { useI18n } from '../i18n';

type TimelineRow =
  | { kind: 'message'; ordinal: number; role: string; text: string }
  | { kind: 'tool'; ordinal: number; role: string; text: string };

type Props = {
  messages: PublicMessage[];
  toolEvents: PublicToolEvent[];
  height?: number;
};

const ESTIMATED_ROW_HEIGHT = 88;
const OVERSCAN = 10;

function estimateHeight(row: TimelineRow) {
  const lines = Math.max(1, Math.ceil(row.text.length / 78));
  return Math.max(ESTIMATED_ROW_HEIGHT, 24 + lines * 24);
}

function lowerBound(values: number[], target: number) {
  let low = 0;
  let high = values.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (values[middle] < target) low = middle + 1;
    else high = middle;
  }
  return Math.min(low, Math.max(0, values.length - 1));
}

export function VirtualTimeline({ messages, toolEvents, height = 560 }: Props) {
  const { t } = useI18n();
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
  const rowElements = useRef(new Map<number, HTMLElement>());
  const [scrollTop, setScrollTop] = useState(0);
  const [measuredHeights, setMeasuredHeights] = useState<Record<number, number>>({});
  const layout = useMemo(() => {
    const offsets: number[] = [];
    let total = 0;
    rows.forEach((row, index) => {
      offsets.push(total);
      total += measuredHeights[index] ?? estimateHeight(row);
    });
    return { offsets, total };
  }, [measuredHeights, rows]);
  const first = rows.length === 0 ? 0 : Math.max(0, lowerBound(layout.offsets, scrollTop) - OVERSCAN);
  const last = rows.length === 0
    ? 0
    : Math.min(rows.length, lowerBound(layout.offsets, scrollTop + height) + OVERSCAN + 1);
  const visible = rows.slice(first, last);

  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return;
    const onScroll = () => setScrollTop(node.scrollTop);
    node.addEventListener('scroll', onScroll, { passive: true });
    return () => node.removeEventListener('scroll', onScroll);
  }, []);

  useLayoutEffect(() => {
    const updates: Record<number, number> = {};
    rowElements.current.forEach((element, index) => {
      const measured = Math.ceil(element.getBoundingClientRect().height);
      if (measured > 0 && Math.abs((measuredHeights[index] ?? 0) - measured) > 1) {
        updates[index] = measured;
      }
    });
    if (Object.keys(updates).length > 0) {
      setMeasuredHeights((current) => ({ ...current, ...updates }));
    }
  }, [first, last, measuredHeights, rows.length]);

  return (
    <div className="timeline" ref={scrollRef} style={{ height }} aria-label={t('timeline.title')}>
      <div style={{ height: layout.total, position: 'relative' }}>
        {visible.map((row, index) => (
          <article
            className="timeline-row"
            data-timeline-row
            key={`${row.kind}-${row.ordinal}`}
            ref={(element) => {
              const absoluteIndex = first + index;
              if (element) rowElements.current.set(absoluteIndex, element);
              else rowElements.current.delete(absoluteIndex);
            }}
            style={{ top: layout.offsets[first + index], minHeight: measuredHeights[first + index] ?? estimateHeight(row) }}
          >
            <span className="timeline-role">{row.role}</span>
            <span className="timeline-text">{row.text}</span>
          </article>
        ))}
      </div>
    </div>
  );
}
