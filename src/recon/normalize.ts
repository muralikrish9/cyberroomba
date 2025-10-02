import { z } from "zod";
import { reconResultSchema, stampMetadata } from "../schemas/index.js";
import type { ReconResult } from "../schemas/index.js";

const subfinderSchema = z.array(
  z.object({
    host: z.string(),
    source: z.string().optional(),
    ip: z.string().optional().nullable(),
  }),
);

const amassSchema = z.object({
  nodes: z
    .array(
      z.object({
        name: z.string(),
        addresses: z.array(z.object({ ip: z.string() })).default([]),
        sources: z.array(z.string()).default([]),
        tag: z.string().optional(),
      }),
    )
    .default([]),
});

const httpxSchema = z.array(
  z.object({
    input: z.string(),
    host: z.string(),
    port: z.number(),
    scheme: z.string(),
    status_code: z.number(),
    title: z.string().optional(),
    webserver: z.string().optional(),
    tech: z.array(z.string()).optional(),
    a: z.array(z.string()).optional(),
    tls: z
      .object({
        issuer_dn: z.string().optional(),
      })
      .optional(),
  }),
);

const securityTrailsSchema = z.object({
  records: z
    .array(
      z.object({
        hostname: z.string(),
        lastSeen: z.string().optional(),
        asn: z.number().optional(),
        organization: z.string().optional(),
        country: z.string().optional(),
        ports: z
          .array(
            z.object({
              port: z.number(),
              protocol: z.string().optional(),
              service: z.string().optional(),
            }),
          )
          .default([]),
      }),
    )
    .default([]),
});

export type ReconInputs = {
  targetId: string;
  primaryTarget: string;
  jobId: string;
  subfinder?: unknown;
  amass?: unknown;
  httpx?: unknown;
  securitytrails?: unknown;
};

const reconResultBase = reconResultSchema.omit({ _id: true });

function ensureArray<T>(value: T[] | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

type HostEntry = {
  host: string;
  ips: Set<string>;
  ports: Map<number, { protocol?: string; service?: string }>;
  tech: Set<string>;
  sources: Set<string>;
  titles: Set<string>;
  webservers: Set<string>;
  liveness: boolean;
};

function upsertHost(map: Map<string, HostEntry>, host: string): HostEntry {
  let record = map.get(host);
  if (!record) {
    record = {
      host,
      ips: new Set(),
      ports: new Map(),
      tech: new Set(),
      sources: new Set(),
      titles: new Set(),
      webservers: new Set(),
      liveness: false,
    };
    map.set(host, record);
  }
  return record;
}

export function normalizeRecon(inputs: ReconInputs): ReconResult[] {
  const hostMap = new Map<string, HostEntry>();
  const sourcesMeta: string[] = [];
  const now = new Date().toISOString();
  const countryByHost = new Map<string, string>();

  if (inputs.subfinder) {
    const parsed = subfinderSchema.safeParse(inputs.subfinder);
    if (parsed.success) {
      sourcesMeta.push('subfinder');
      parsed.data.forEach((entry) => {
        const hostRecord = upsertHost(hostMap, entry.host);
        if (entry.ip) hostRecord.ips.add(entry.ip);
        if (entry.source) hostRecord.sources.add(`subfinder:${entry.source}`);
      });
    }
  }

  if (inputs.amass) {
    const parsed = amassSchema.safeParse(inputs.amass);
    if (parsed.success) {
      sourcesMeta.push('amass');
      parsed.data.nodes.forEach((node) => {
        const hostRecord = upsertHost(hostMap, node.name);
        ensureArray(node.addresses).forEach((addr) => hostRecord.ips.add(addr.ip));
        ensureArray(node.sources).forEach((src) => hostRecord.sources.add(`amass:${src}`));
      });
    }
  }

  if (inputs.httpx) {
    const parsed = httpxSchema.safeParse(inputs.httpx);
    if (parsed.success) {
      sourcesMeta.push('httpx');
      parsed.data.forEach((entry) => {
        const hostRecord = upsertHost(hostMap, entry.host);
        hostRecord.liveness = hostRecord.liveness || entry.status_code < 500;
        if (entry.title) hostRecord.titles.add(entry.title);
        if (entry.webserver) hostRecord.webservers.add(entry.webserver);
        ensureArray(entry.tech).forEach((t) => hostRecord.tech.add(t));
        ensureArray(entry.a).forEach((ip) => hostRecord.ips.add(ip));
        const portInfo: { protocol?: string; service?: string } = hostRecord.ports.get(entry.port) ?? {};
        portInfo.protocol = portInfo.protocol ?? 'tcp';
        portInfo.service = portInfo.service ?? entry.scheme;
        hostRecord.ports.set(entry.port, portInfo);
      });
    }
  }

  if (inputs.securitytrails) {
    const parsed = securityTrailsSchema.safeParse(inputs.securitytrails);
    if (parsed.success) {
      sourcesMeta.push('securitytrails');
      parsed.data.records.forEach((record) => {
        const hostRecord = upsertHost(hostMap, record.hostname);
        if (record.organization) hostRecord.sources.add(`securitytrails:${record.organization}`);
        if (record.country) countryByHost.set(record.hostname, record.country);
        ensureArray(record.ports).forEach((p) => {
          const info: { protocol?: string; service?: string } = hostRecord.ports.get(p.port) ?? {};
          if (p.protocol) {
            info.protocol = info.protocol ?? p.protocol;
          }
          if (p.service) {
            info.service = info.service ?? p.service;
          }
          hostRecord.ports.set(p.port, info);
        });
      });
    }
  }

  const results: ReconResult[] = [];

  hostMap.forEach((entry) => {
    const ipValue = Array.from(entry.ips)[0];
    const ports = Array.from(entry.ports.entries()).map(([port, data]) => ({
      port,
      protocol: data.protocol ?? 'tcp',
      service: data.service,
    }));

    const tech = Array.from(entry.tech).map((name) => ({ name }));

    const fingerprints: Record<string, unknown> = {
      titles: Array.from(entry.titles),
      webservers: Array.from(entry.webservers),
    };
    const country = countryByHost.get(entry.host);
    if (country) {
      fingerprints.country = country;
    }

    const base: Record<string, unknown> = {
      targetId: inputs.targetId,
      subdomain: entry.host,
      ip: ipValue,
      ports,
      tech,
      fingerprints,
      sources: [
        {
          tool: 'recon-normalize',
          runId: inputs.jobId,
          details: {
            contributors: Array.from(entry.sources),
            pipeline: sourcesMeta,
          },
        },
      ],
      isAlive: entry.liveness,
      lastChecked: now,
    };

    const stamped = stampMetadata(base as any);
    const parsed = reconResultBase.parse(stamped) as ReconResult;
    results.push(parsed);
  });

  return results;
}

export const ReconNormalization = {
  subfinderSchema,
  amassSchema,
  httpxSchema,
  securityTrailsSchema,
  normalizeRecon,
};
