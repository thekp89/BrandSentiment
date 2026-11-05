"""
Multi-Channel Alert Dispatcher for Brand Sentinel
Supports Slack, Discord, Telegram, Generic Webhooks, and SMTP.
"""
import os
import json
import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

def send_slack_alert(webhook_url, title, details, severity="CRÍTICO", link=None):
    if not webhook_url:
        return False, "URL de webhook no provista"
    
    color = "#f7768e" if severity in ["CRÍTICO", "CRITICO"] else ("#e0af68" if severity == "ALTO" else "#7aa2f7")
    payload = {
        "attachments": [
            {
                "color": color,
                "title": f"[{severity}] {title}",
                "text": details,
                "fields": [
                    {"title": "Severidad", "value": severity, "short": True},
                    {"title": "Fecha", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "short": True}
                ],
                "footer": "Brand Sentinel Intelligence"
            }
        ]
    }
    if link:
        payload["attachments"][0]["title_link"] = link
        payload["attachments"][0]["fields"].append({"title": "Fuente / Enlace", "value": link, "short": False})
        
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def send_discord_alert(webhook_url, title, details, severity="CRÍTICO", link=None):
    if not webhook_url:
        return False, "URL de webhook no provista"
    
    color = 16218766 if severity in ["CRÍTICO", "CRITICO"] else (14725224 if severity == "ALTO" else 8037111)
    embed = {
        "title": f"🚨 [{severity}] {title}",
        "description": details,
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "footer": {"text": "Brand Sentinel Security & OSINT"}
    }
    if link:
        embed["url"] = link
        embed["fields"] = [{"name": "Enlace", "value": link}]
        
    payload = {"embeds": [embed]}
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        return r.status_code in [200, 204], f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def send_telegram_alert(bot_token, chat_id, title, details, severity="CRÍTICO", link=None):
    if not bot_token or not chat_id:
        return False, "Token o Chat ID de Telegram no provisto"
        
    msg = f"🚨 *[{severity}] {title}*\n\n{details}\n\n📅 _{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
    if link:
        msg += f"\n🔗 [Ver Enlace]({link})"
        
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": msg,
        "parse_mode": "Markdown",
        "disable_web_page_preview": False
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def send_generic_webhook_alert(webhook_url, title, details, severity="CRÍTICO", link=None, entity=None):
    if not webhook_url:
        return False, "URL de webhook no provista"
        
    payload = {
        "source": "Brand Sentinel",
        "severity": severity,
        "title": title,
        "details": details,
        "link": link,
        "entity": entity,
        "timestamp": datetime.now().isoformat()
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        return r.status_code in [200, 201, 202, 204], f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def dispatch_alerts(title, details, severity="CRÍTICO", link=None, entity=None):
    """
    Broadcasts alert to all configured notification channels in environment.
    Returns dict with channel results.
    """
    results = {}
    
    # 1. Slack
    slack_url = os.getenv("SLACK_WEBHOOK_URL")
    if slack_url:
        ok, msg = send_slack_alert(slack_url, title, details, severity, link)
        results["slack"] = {"success": ok, "message": msg}
        
    # 2. Discord
    discord_url = os.getenv("DISCORD_WEBHOOK_URL")
    if discord_url:
        ok, msg = send_discord_alert(discord_url, title, details, severity, link)
        results["discord"] = {"success": ok, "message": msg}
        
    # 3. Telegram
    tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
    tg_chat = os.getenv("TELEGRAM_CHAT_ID")
    if tg_token and tg_chat:
        ok, msg = send_telegram_alert(tg_token, tg_chat, title, details, severity, link)
        results["telegram"] = {"success": ok, "message": msg}
        
    # 4. Generic Webhook
    generic_url = os.getenv("GENERIC_WEBHOOK_URL")
    if generic_url:
        ok, msg = send_generic_webhook_alert(generic_url, title, details, severity, link, entity)
        results["generic_webhook"] = {"success": ok, "message": msg}
        
    return results
