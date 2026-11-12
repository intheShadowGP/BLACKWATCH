import { z } from 'zod';

// Zod compiles object parsers with `new Function` when it can, and probes for that ability on first
// use. The Content Security Policy forbids eval: the probe fails as intended, but browsers still
// report it as a policy violation (Firefox on the console). Jitless mode skips the probe and uses
// the interpreted parsers. Imported first by the application entry point.
z.config({ jitless: true });
