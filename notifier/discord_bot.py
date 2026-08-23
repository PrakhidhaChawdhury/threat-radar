"""
notifier/discord_bot.py — Interactive Discord Bot with /scan Slash Command.

Allows developers and builders to forward suspicious job recruiter DMs,
take-home task repos, npm packages, or Telegram offers directly inside Discord
to get an instant, Gemini 3.7-evaluated and SQLite-campaign-matched verdict.

Features:
  - Slash command: `/scan text:<suspicious text or URL>`
  - DM scanner: Directly forwards DMs to the threat scanner
  - Mention scanner: `@ThreatRadar scan <text>` in any server channel
"""

import os
import discord
from discord import app_commands
from discord.ext import commands

import config
from engine.scanner import scan_suspicious_input, ScanVerdict

# Intent permissions
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!radar ", intents=intents)


def format_scan_embed(verdict: ScanVerdict, original_text: str) -> discord.Embed:
    """Format a ScanVerdict into a rich Discord embed matching the ThreatRadar design system."""
    color_map = {
        "CRITICAL_SCAM": 0xFF3366,  # Crimson
        "SUSPICIOUS":    0xF59E0B,  # Amber
        "LIKELY_SAFE":   0x10B981,  # Emerald
    }
    emoji_map = {
        "CRITICAL_SCAM": "🚨",
        "SUSPICIOUS":    "⚠️",
        "LIKELY_SAFE":   "✅",
    }
    
    color = color_map.get(verdict.verdict, 0x3B82F6)
    emoji = emoji_map.get(verdict.verdict, "🔍")
    
    embed = discord.Embed(
        title=f"{emoji} Threat Verdict: {verdict.verdict.replace('_', ' ')}",
        description=f"**Category:** `{verdict.threat_category}`\n**Confidence:** `{verdict.confidence_score:.0%}`",
        color=color,
    )
    
    # The Hidden Trap
    embed.add_field(
        name="🪤 The Hidden Trap",
        value=verdict.plain_english_trap or "_No specific trap detected._",
        inline=False,
    )
    
    # Red Flags
    if verdict.red_flags_detected:
        flags_text = "\n".join(f"• {flag}" for flag in verdict.red_flags_detected)
        embed.add_field(name="🚩 Red Flags Detected", value=flags_text, inline=False)
        
    # Action Steps
    if verdict.immediate_safety_steps:
        steps_text = "\n".join(f"**{i+1}.** {step}" for i, step in enumerate(verdict.immediate_safety_steps))
        embed.add_field(name="🛡️ Recommended Actions", value=steps_text, inline=False)
        
    # Matched Outbreak Campaign
    if verdict.matched_campaign_fingerprint:
        embed.add_field(
            name="🧬 Matched Outbreak Campaign",
            value=f"`{verdict.matched_campaign_fingerprint}`",
            inline=True,
        )
        
    embed.set_footer(text="ThreatRadar Autonomous Intelligence • Powered by Bright Data & Gemini 3.7")
    return embed


@bot.event
async def on_ready():
    """Triggered when the bot connects to Discord."""
    print(f"[DISCORD BOT] Logged in as {bot.user} (ID: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        print(f"[DISCORD BOT] Synced {len(synced)} slash command(s).")
    except Exception as e:
        print(f"[DISCORD BOT] Error syncing slash commands: {e}")


@bot.tree.command(name="scan", description="Scan a suspicious recruiter DM, GitHub repo, npm package, or Telegram offer")
@app_commands.describe(text="The suspicious message, code snippet, repo URL, or package name to scan")
async def slash_scan(interaction: discord.Interaction, text: str):
    """Slash command: /scan <text>."""
    await interaction.response.defer(thinking=True)
    
    try:
        verdict = await scan_suspicious_input(text)
        embed = format_scan_embed(verdict, text)
        await interaction.followup.send(embed=embed)
    except Exception as e:
        await interaction.followup.send(f"⚠️ Scan failed: {e}")


@bot.event
async def on_message(message: discord.Message):
    """Listen for direct messages or @mentions asking to scan."""
    if message.author == bot.user:
        return

    # DM Scanner: automatically scan any direct message sent to the bot
    if isinstance(message.channel, discord.DMChannel):
        async with message.channel.typing():
            try:
                verdict = await scan_suspicious_input(message.content)
                embed = format_scan_embed(verdict, message.content)
                await message.reply(embed=embed)
            except Exception as e:
                await message.reply(f"⚠️ Scan failed: {e}")
        return

    # Mention Scanner: @ThreatRadar scan <text>
    if bot.user in message.mentions and "scan" in message.content.lower():
        clean_content = message.content.replace(f"<@{bot.user.id}>", "").replace("scan", "", 1).strip()
        if clean_content:
            async with message.channel.typing():
                try:
                    verdict = await scan_suspicious_input(clean_content)
                    embed = format_scan_embed(verdict, clean_content)
                    await message.reply(embed=embed)
                except Exception as e:
                    await message.reply(f"⚠️ Scan failed: {e}")
        return

    await bot.process_commands(message)


def run_bot(token: str | None = None):
    """Entry point to launch the Discord bot."""
    bot_token = token or os.environ.get("DISCORD_BOT_TOKEN")
    if not bot_token:
        print("[DISCORD BOT] ⚠️  No DISCORD_BOT_TOKEN found in environment.")
        print("[DISCORD BOT] Set DISCORD_BOT_TOKEN in .env to run the live interactive bot.")
        return
    bot.run(bot_token)


if __name__ == "__main__":
    run_bot()
