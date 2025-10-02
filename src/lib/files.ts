import { mkdir, writeFile as fsWriteFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

export async function writeJsonFile(filePath: string, data: unknown): Promise<void> {
  const fullPath = resolve(filePath);
  await mkdir(dirname(fullPath), { recursive: true });
  await fsWriteFile(fullPath, JSON.stringify(data, null, 2), 'utf8');
}

export async function writeFile(filePath: string, content: string): Promise<void> {
  const fullPath = resolve(filePath);
  await mkdir(dirname(fullPath), { recursive: true });
  await fsWriteFile(fullPath, content, 'utf8');
}
