import { lazy, type ComponentType, type LazyExoticComponent } from 'react';
import type { MessageKey } from '../i18n';

export type ToolCategory = 'hashing' | 'encoding' | 'analysis' | 'network' | 'web' | 'reference' | 'rules' | 'files';

export interface ToolDefinition {
  id: string;
  category: ToolCategory;
  titleKey: MessageKey;
  summaryKey: MessageKey;
  limitsKey: MessageKey;
  component: LazyExoticComponent<ComponentType>;
}

const load = <K extends string>(loader: () => Promise<Record<K, ComponentType>>, name: K) =>
  lazy(async () => ({ default: (await loader())[name] }));

const encoding = () => import('./tools/encoding');
const analysis = () => import('./tools/analysis');
const network = () => import('./tools/network');
const reference = () => import('./tools/reference');
const rules = () => import('./tools/rules');
const files = () => import('./tools/files');

const tool = (id: string, category: ToolCategory, component: LazyExoticComponent<ComponentType>): ToolDefinition => ({
  id,
  category,
  titleKey: `tool.${id}.title` as MessageKey,
  summaryKey: `tool.${id}.summary` as MessageKey,
  limitsKey: `tool.${id}.limits` as MessageKey,
  component,
});

export const TOOLS: readonly ToolDefinition[] = [
  tool('hash-text', 'hashing', load(encoding, 'HashTextTool')),
  tool('hash-file', 'hashing', load(files, 'HashFileTool')),
  tool('base64', 'encoding', load(encoding, 'Base64Tool')),
  tool('hex', 'encoding', load(encoding, 'HexTool')),
  tool('entropy', 'analysis', load(files, 'EntropyTool')),
  tool('jwt', 'analysis', load(analysis, 'JwtTool')),
  tool('json', 'analysis', load(analysis, 'JsonTool')),
  tool('url', 'web', load(analysis, 'UrlTool')),
  tool('ioc', 'analysis', load(analysis, 'IocTool')),
  tool('regex', 'analysis', load(analysis, 'RegexTool')),
  tool('ipv4', 'network', load(network, 'Ipv4Tool')),
  tool('ipv6', 'network', load(network, 'Ipv6Tool')),
  tool('cidr', 'network', load(network, 'CidrTool')),
  tool('ports', 'network', load(network, 'PortsTool')),
  tool('headers', 'web', load(analysis, 'HeadersTool')),
  tool('password', 'analysis', load(analysis, 'PasswordTool')),
  tool('tls', 'reference', load(reference, 'TlsTool')),
  tool('sigma', 'rules', load(rules, 'SigmaTool')),
  tool('yara', 'rules', load(rules, 'YaraTool')),
  tool('file-meta', 'files', load(files, 'FileMetaTool')),
];

export const CATEGORIES: readonly ToolCategory[] = ['hashing', 'encoding', 'analysis', 'web', 'network', 'files', 'rules', 'reference'];

/**
 * The 23 utilities required by the product specification, mapped to the tool
 * that provides each one. Several requirements share a tool (the three SHA-2
 * sizes; JSON formatting and validation).
 */
export const SPECIFICATION_COVERAGE: Readonly<Record<string, string>> = {
  'SHA-256': 'hash-text',
  'SHA-384': 'hash-text',
  'SHA-512': 'hash-text',
  'File hashing': 'hash-file',
  'Base64 encoder and decoder': 'base64',
  'Hexadecimal converter': 'hex',
  'Entropy calculator': 'entropy',
  'JWT structural decoder': 'jwt',
  'JSON formatter': 'json',
  'JSON validator': 'json',
  'URL parser': 'url',
  'IOC extractor': 'ioc',
  'Regular expression tester': 'regex',
  'IPv4 calculator': 'ipv4',
  'IPv6 calculator': 'ipv6',
  'CIDR and subnet calculator': 'cidr',
  'Port reference': 'ports',
  'HTTP header analyzer': 'headers',
  'Local password strength estimator': 'password',
  'TLS reference': 'tls',
  'Sigma viewer': 'sigma',
  'YARA viewer': 'yara',
  'File metadata inspector': 'file-meta',
};

export function findTool(id: string): ToolDefinition | undefined {
  return TOOLS.find((entry) => entry.id === id);
}
