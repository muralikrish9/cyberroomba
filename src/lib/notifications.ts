import { config } from './config.js';
import type { Vulnerability, JobRun } from '../schemas/index.js';

export interface DiscordEmbed {
  title: string;
  description?: string;
  color?: number;
  fields?: Array<{
    name: string;
    value: string;
    inline?: boolean;
  }>;
  footer?: {
    text: string;
  };
  timestamp?: string;
}

export interface DiscordWebhookPayload {
  content?: string;
  embeds?: DiscordEmbed[];
  username?: string;
  avatar_url?: string;
}

interface DiscordChannelConfig {
  critical: string;
  high: string;
  medium: string;
  low: string;
  info: string;
  reports: string;
  dailySummary: string;
}

class NotificationService {
  private discordWebhook: string;
  private channelConfig: DiscordChannelConfig;

  constructor() {
    this.discordWebhook = config.discordWebhook;
    
    // Parse channel configuration from environment
    this.channelConfig = {
      critical: process.env.DISCORD_CRITICAL_CHANNEL || '',
      high: process.env.DISCORD_HIGH_CHANNEL || '',
      medium: process.env.DISCORD_MEDIUM_CHANNEL || '',
      low: process.env.DISCORD_LOW_CHANNEL || '',
      info: process.env.DISCORD_INFO_CHANNEL || '',
      reports: process.env.DISCORD_REPORTS_CHANNEL || '',
      dailySummary: process.env.DISCORD_DAILY_SUMMARY_CHANNEL || '',
    };
  }

  private async sendDiscordWebhook(payload: DiscordWebhookPayload, channelType?: keyof DiscordChannelConfig): Promise<void> {
    let webhookUrl = this.discordWebhook;
    
    // Use channel-specific webhook if configured
    if (channelType && this.channelConfig[channelType]) {
      webhookUrl = this.channelConfig[channelType];
    }
    
    if (!webhookUrl) {
      console.warn(`[notifications] Discord webhook not configured for ${channelType || 'default'}, skipping notification`);
      return;
    }

    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Discord webhook failed: ${response.status} ${response.statusText}`);
      }

      console.log(`[notifications] Discord notification sent successfully to ${channelType || 'default'} channel`);
    } catch (error) {
      console.error('[notifications] Failed to send Discord notification:', (error as Error).message);
    }
  }

  private getSeverityColor(severity: string): number {
    const colors = {
      critical: 0xff0000, // Red
      high: 0xff6600,     // Orange
      medium: 0xffff00,   // Yellow
      low: 0x00ff00,      // Green
      info: 0x0099ff,     // Blue
    };
    return colors[severity as keyof typeof colors] || 0x666666;
  }

  async notifyVulnerabilityFinding(vulnerability: Vulnerability, reconHost: string): Promise<void> {
    // Route all severity levels to appropriate channels
    await this.notifyHighSeverityFinding(vulnerability, reconHost);
  }

  async notifyHighSeverityFinding(vulnerability: Vulnerability, reconHost: string): Promise<void> {
    const severity = vulnerability.severity.toLowerCase();
    const severityUpper = severity.toUpperCase();
    const color = this.getSeverityColor(severity);

    // Determine which channel to send to based on severity
    const channelType = severity as keyof DiscordChannelConfig;
    
    // Get appropriate emoji and urgency level
    const emoji = this.getSeverityEmoji(severity);
    const urgencyText = severity === 'critical' ? '🚨 IMMEDIATE ATTENTION REQUIRED 🚨' : 
                       severity === 'high' ? '⚠️ High Priority' : 
                       '🔶 Medium Priority';

    const embed: DiscordEmbed = {
      title: `${emoji} ${severityUpper} Vulnerability Found`,
      description: `**${vulnerability.title}**\n${vulnerability.description || 'No description available'}`,
      color,
      fields: [
        {
          name: '🎯 Target',
          value: `\`${reconHost}\``,
          inline: true,
        },
        {
          name: '📊 Confidence',
          value: vulnerability.confidence,
          inline: true,
        },
        {
          name: '🏷️ Category',
          value: vulnerability.category || 'Unknown',
          inline: true,
        },
        {
          name: '🔍 Source',
          value: vulnerability.source,
          inline: true,
        },
        {
          name: '📅 Found',
          value: new Date(vulnerability.createdAt).toLocaleString(),
          inline: true,
        },
        {
          name: '📝 Status',
          value: vulnerability.status,
          inline: true,
        },
      ],
      footer: {
        text: `CyberRoomba • Finding ID: ${vulnerability._id}`,
      },
      timestamp: new Date().toISOString(),
    };

    // Add CVE information if available
    if (vulnerability.cves && vulnerability.cves.length > 0) {
      const cveList = vulnerability.cves.map(cve => {
        const cvss = cve.cvss?.baseScore ? ` (CVSS: ${cve.cvss.baseScore})` : '';
        return `• ${cve.id}${cvss}`;
      }).join('\n');
      
      embed.fields!.push({
        name: '🔒 CVEs',
        value: cveList,
        inline: false,
      });
    }

    // Add channel identifier to distinguish notifications
    const channelIdentifier = severity === 'critical' ? '🚨 **CRITICAL CHANNEL** 🚨' :
                             severity === 'high' ? '⚠️ **HIGH CHANNEL** ⚠️' :
                             severity === 'medium' ? '🔶 **MEDIUM CHANNEL** 🔶' :
                             severity === 'low' ? '🔸 **LOW CHANNEL** 🔸' :
                             'ℹ️ **INFO CHANNEL** ℹ️';

    const payload: DiscordWebhookPayload = {
      content: `${channelIdentifier}\n${urgencyText}\n**New ${severityUpper} vulnerability discovered!**`,
      embeds: [embed],
      username: `CyberRoomba-${severity.toUpperCase()}`,
      avatar_url: 'https://cdn.discordapp.com/embed/avatars/0.png',
    };

    await this.sendDiscordWebhook(payload, channelType);
  }

  private getSeverityEmoji(severity: string): string {
    const emojis = {
      critical: '🚨',
      high: '⚠️',
      medium: '🔶',
      low: '🔸',
      info: 'ℹ️',
    };
    return emojis[severity as keyof typeof emojis] || '🔸';
  }

  async notifyJobCompletion(job: JobRun, stats?: Record<string, unknown>): Promise<void> {
    const status = job.status.toUpperCase();
    const color = job.status === 'success' ? 0x00ff00 : job.status === 'failed' ? 0xff0000 : 0xffff00;
    const emoji = job.status === 'success' ? '✅' : job.status === 'failed' ? '❌' : '⏳';

    const embed: DiscordEmbed = {
      title: `${emoji} Job ${status}`,
      description: `**${job.workflow}** workflow completed`,
      color,
      fields: [
        {
          name: '🕒 Duration',
          value: job.durationMs ? `${Math.round(job.durationMs / 1000)}s` : 'Unknown',
          inline: true,
        },
        {
          name: '🎯 Trigger',
          value: job.trigger,
          inline: true,
        },
        {
          name: '📊 Stats',
          value: stats ? JSON.stringify(stats, null, 2) : 'No stats available',
          inline: false,
        },
      ],
      footer: {
        text: `Job ID: ${(job as any).jobId}`,
      },
      timestamp: new Date().toISOString(),
    };

    if (job.error) {
      embed.fields!.push({
        name: '❌ Error',
        value: `\`\`\`${job.error.message}\`\`\``,
        inline: false,
      });
    }

    const payload: DiscordWebhookPayload = {
      content: `**Workflow ${status.toLowerCase()}!**`,
      embeds: [embed],
      username: 'CyberRoomba',
    };

    // Send job completion to info channel or default
    await this.sendDiscordWebhook(payload, 'info');
  }

  async notifyDailySummary(summary: {
    totalTargets: number;
    totalHosts: number;
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    newFindings: number;
  }): Promise<void> {
    const embed: DiscordEmbed = {
      title: '📊 Daily Summary',
      description: 'CyberRoomba automation pipeline summary',
      color: 0x0099ff,
      fields: [
        {
          name: '🎯 Total Targets',
          value: summary.totalTargets.toString(),
          inline: true,
        },
        {
          name: '🖥️ Hosts Discovered',
          value: summary.totalHosts.toString(),
          inline: true,
        },
        {
          name: '🔍 Total Vulnerabilities',
          value: summary.totalVulnerabilities.toString(),
          inline: true,
        },
        {
          name: '🚨 Critical',
          value: summary.criticalCount.toString(),
          inline: true,
        },
        {
          name: '⚠️ High',
          value: summary.highCount.toString(),
          inline: true,
        },
        {
          name: '🆕 New Today',
          value: summary.newFindings.toString(),
          inline: true,
        },
      ],
      footer: {
        text: 'CyberRoomba • Daily Report',
      },
      timestamp: new Date().toISOString(),
    };

    const payload: DiscordWebhookPayload = {
      content: '**Daily automation summary** 📈',
      embeds: [embed],
      username: 'CyberRoomba',
    };

    // Send daily summary to dedicated channel or default
    await this.sendDiscordWebhook(payload, 'dailySummary');
  }
}

export const notificationService = new NotificationService();
