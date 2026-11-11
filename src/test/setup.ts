import 'fake-indexeddb/auto';
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';
import { clearDatasetCache } from '../data/loader';

// jsdom does not implement modal dialogs: minimal stand-ins that track the open state.
if (typeof HTMLDialogElement.prototype.showModal !== 'function') {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute('open', '');
  };
}
if (typeof HTMLDialogElement.prototype.close !== 'function') {
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.removeAttribute('open');
    this.dispatchEvent(new Event('close'));
  };
}

window.scrollTo = () => undefined;

// No test may reach the network: by default every dataset request answers 404
// ("not published"). Tests that need data install fixtures with mockDatasets().
beforeEach(() => {
  clearDatasetCache();
  vi.stubGlobal('fetch', vi.fn(async () => new Response('Not found', { status: 404 })));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
