export type CommandConfig = {
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd?: string;
};

const BIN_DIR = process.env.RECON_BIN_DIR || 'C:/Tools/bin';
const defaultCwd = process.env.RECON_WORKDIR || process.cwd();

function buildCommand(binary: string, args: string[]): CommandConfig {
  return {
    command: `${BIN_DIR}/${binary}`.replace(/\\/g, '/'),
    args,
    cwd: defaultCwd,
  };
}

export function subfinderCommand(domain: string): CommandConfig {
  return buildCommand('subfinder.exe', ['-d', domain, '-json']);
}

export function amassCommand(domain: string): CommandConfig {
  return buildCommand('amass.exe', ['enum', '-d', domain, '-json']);
}

export function httpxCommand(hostsFile: string): CommandConfig {
  return buildCommand('httpx.exe', ['-l', hostsFile, '-json', '-follow-redirects', '-status-code', '-title', '-tech-detect']);
}

export function masscanCommand(target: string, ports = '80,443,8000-8100'): CommandConfig {
  return buildCommand('masscan.exe', ['-p', ports, target, '--rate', '2000', '--wait', '0']);
}

export function nmapCommand(target: string): CommandConfig {
  return buildCommand('nmap.exe', ['-sV', '-Pn', '-T4', '-oX', '-', target]);
}

export function whatwebCommand(target: string): CommandConfig {
  return buildCommand('whatweb.bat', ['--no-errors', '--log-json=-', target]);
}

export function dnsxCommand(hostsFile: string): CommandConfig {
  return buildCommand('dnsx.exe', ['-l', hostsFile, '-json']);
}

export function jobArtifactsDir(jobId: string): string {
  const base = process.env.RECON_RAW_DIR || 'data/recon/raw';
  return `${base}/${jobId}`.replace(/\\/g, '/');
}
