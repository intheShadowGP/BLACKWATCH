import { executeRegex, type RegexRequest } from '../lib/regex';

self.onmessage = (event: MessageEvent<RegexRequest>) => {
  self.postMessage(executeRegex(event.data));
};
