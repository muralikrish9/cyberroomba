# Discord Channel Setup for CyberRoomba

## Required Discord Channels

Create the following channels in your Discord server for organized vulnerability notifications:

### 🚨 Critical Vulnerabilities
- **Channel Name:** `#critical-vulns`
- **Purpose:** Immediate attention required vulnerabilities
- **Webhook URL:** `DISCORD_CRITICAL_CHANNEL`

### ⚠️ High Priority Vulnerabilities  
- **Channel Name:** `#high-vulns`
- **Purpose:** High priority vulnerabilities
- **Webhook URL:** `DISCORD_HIGH_CHANNEL`

### 🔶 Medium Priority Vulnerabilities
- **Channel Name:** `#medium-vulns`
- **Purpose:** Medium priority vulnerabilities
- **Webhook URL:** `DISCORD_MEDIUM_CHANNEL`

### 🔸 Low Priority Vulnerabilities
- **Channel Name:** `#low-vulns`
- **Purpose:** Low priority vulnerabilities
- **Webhook URL:** `DISCORD_LOW_CHANNEL`

### ℹ️ Info & Job Status
- **Channel Name:** `#cyberroomba-info`
- **Purpose:** Job completions, system status, general info
- **Webhook URL:** `DISCORD_INFO_CHANNEL`

### 📊 Daily Summary
- **Channel Name:** `#daily-summary`
- **Purpose:** Daily automation summaries and statistics
- **Webhook URL:** `DISCORD_DAILY_SUMMARY_CHANNEL`

### 📋 Reports
- **Channel Name:** `#vulnerability-reports`
- **Purpose:** Generated vulnerability reports
- **Webhook URL:** `DISCORD_REPORTS_CHANNEL`

## Environment Configuration

Add these webhook URLs to your `.env.local` file:

```bash
# Discord Channel Webhooks
DISCORD_CRITICAL_CHANNEL=https://discord.com/api/webhooks/YOUR_CRITICAL_WEBHOOK
DISCORD_HIGH_CHANNEL=https://discord.com/api/webhooks/YOUR_HIGH_WEBHOOK
DISCORD_MEDIUM_CHANNEL=https://discord.com/api/webhooks/YOUR_MEDIUM_WEBHOOK
DISCORD_LOW_CHANNEL=https://discord.com/api/webhooks/YOUR_LOW_WEBHOOK
DISCORD_INFO_CHANNEL=https://discord.com/api/webhooks/YOUR_INFO_WEBHOOK
DISCORD_DAILY_SUMMARY_CHANNEL=https://discord.com/api/webhooks/YOUR_SUMMARY_WEBHOOK
DISCORD_REPORTS_CHANNEL=https://discord.com/api/webhooks/YOUR_REPORTS_WEBHOOK

# Fallback webhook (if channel-specific webhooks are not configured)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1422803513171247227/BToAMTWZRMtwDyKwnVs-0yLl3ZDXA_b_5JbLYk-euIfJHrUGzspP5JuiRPDcSf39jSNq
```

## How to Create Discord Webhooks

1. **Go to your Discord server settings**
2. **Navigate to Integrations → Webhooks**
3. **Click "Create Webhook"**
4. **Configure each webhook:**
   - **Name:** CyberRoomba Critical (or appropriate name)
   - **Channel:** Select the appropriate channel
   - **Copy the webhook URL**
5. **Repeat for each channel**

## Notification Routing

The system will automatically route notifications based on severity:

- **🚨 Critical** → `#critical-vulns`
- **⚠️ High** → `#high-vulns`  
- **🔶 Medium** → `#medium-vulns`
- **🔸 Low** → `#low-vulns`
- **ℹ️ Info** → `#cyberroomba-info`
- **📊 Daily Summary** → `#daily-summary`
- **📋 Reports** → `#vulnerability-reports`

If a channel-specific webhook is not configured, notifications will fall back to the default `DISCORD_WEBHOOK_URL`.

## Testing

Run the following command to test all channels:

```bash
npm run vuln:run
```

This will send test notifications to all configured channels based on the vulnerabilities found.
