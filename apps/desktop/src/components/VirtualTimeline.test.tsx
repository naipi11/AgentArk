import { render, screen } from '@testing-library/react';
import { expect, test } from 'vitest';
import { VirtualTimeline } from './VirtualTimeline';

test('renders hostile text literally without creating an image element', () => {
  render(<VirtualTimeline messages={[{ ordinal: 1, role: 'user', text: '<img src=x onerror=DesktopXssCanary>' }]} toolEvents={[]} height={200} />);
  expect(screen.getByText('<img src=x onerror=DesktopXssCanary>')).toBeInTheDocument();
  expect(document.querySelector('img')).toBeNull();
});

test('mounts fewer than forty rows for a ten-thousand-message viewport', () => {
  const messages = Array.from({ length: 10_000 }, (_, ordinal) => ({ ordinal, role: 'user', text: `message-${ordinal}` }));
  render(<VirtualTimeline messages={messages} toolEvents={[]} height={720} />);
  expect(document.querySelectorAll('[data-timeline-row]').length).toBeLessThan(40);
});
