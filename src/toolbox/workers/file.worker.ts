import { analyzeBlob } from '../lib/file';

self.onmessage = async (event: MessageEvent<Blob>) => {
  self.postMessage(await analyzeBlob(event.data));
};
