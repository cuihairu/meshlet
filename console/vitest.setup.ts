import { vi } from 'vitest';

// antd's responsive observer (useBreakpoint / Pagination) calls
// window.matchMedia, which jsdom does not implement. Polyfill it so antd
// components can mount in tests.
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }),
});

// antd Select / Tooltip use @rc-component/resize-observer, which needs
// ResizeObserver — jsdom does not implement it. Polyfill with a no-op.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver =
  globalThis.ResizeObserver ?? (ResizeObserverStub as unknown as typeof ResizeObserver);
