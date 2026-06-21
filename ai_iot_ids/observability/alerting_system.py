"""
Alerting and notification system for AI-driven IoT IDS.

This module provides multi-channel alerting capabilities including
email, Slack, webhooks, and Kibana dashboard management.
"""

import json
import logging
import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import asyncio
from urllib.parse import urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None

try:
    from slack_sdk import WebClient
    from slack_sdk.errors import SlackApiError
except ImportError:
    WebClient = None
    SlackApiError = Exception

from ..models.threat_detection import ThreatDetection, SeverityLevel
from ..utils.error_handling import IDSError


@dataclass
class EmailConfig:
    """Configuration for email alerting."""
    smtp_server: str
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    sender_email: str = ""
    sender_name: str = "AI-IoT IDS"
    recipients: List[str] = None
    
    def __post_init__(self):
        if self.recipients is None:
            self.recipients = []


@dataclass
class SlackConfig:
    """Configuration for Slack alerting."""
    bot_token: str
    channel: str
    username: str = "AI-IoT IDS"
    icon_emoji: str = ":shield:"
    mention_users: List[str] = None
    
    def __post_init__(self):
        if self.mention_users is None:
            self.mention_users = []


@dataclass
class WebhookConfig:
    """Configuration for webhook notifications."""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = None
    auth_token: Optional[str] = None
    timeout: int = 30
    retry_attempts: int = 3
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}


@dataclass
class KibanaConfig:
    """Configuration for Kibana dashboard management."""
    base_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    space_id: str = "default"
    timeout: int = 30


@dataclass
class AlertRule:
    """Configuration for alert rule."""
    name: str
    severity_threshold: SeverityLevel = SeverityLevel.MEDIUM
    threat_score_threshold: float = 0.7
    confidence_threshold: float = 0.8
    enabled: bool = True
    cooldown_minutes: int = 15
    max_alerts_per_hour: int = 10


class EmailAlerter:
    """Email alerting functionality."""
    
    def __init__(self, config: EmailConfig):
        """
        Initialize email alerter.
        
        Args:
            config: Email configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._last_alert_times = {}
    
    def send_threat_alert(self, detection: ThreatDetection, additional_context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send threat detection alert via email.
        
        Args:
            detection: Threat detection data
            additional_context: Additional context information
            
        Returns:
            True if email was sent successfully
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = f"{self.config.sender_name} <{self.config.sender_email}>"
            msg['To'] = ", ".join(self.config.recipients)
            msg['Subject'] = f"[{detection.severity.value.upper()}] Threat Detected - {detection.attack_category.value if detection.attack_category else 'Unknown'}"
            
            # Create email body
            body = self._create_threat_email_body(detection, additional_context)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            return self._send_email(msg)
            
        except Exception as e:
            self.logger.error(f"Failed to send threat alert email: {e}")
            return False
    
    def send_system_alert(self, title: str, message: str, severity: str = "INFO", **kwargs) -> bool:
        """
        Send system alert via email.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            **kwargs: Additional context
            
        Returns:
            True if email was sent successfully
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = f"{self.config.sender_name} <{self.config.sender_email}>"
            msg['To'] = ", ".join(self.config.recipients)
            msg['Subject'] = f"[{severity}] {title}"
            
            # Create email body
            body = self._create_system_email_body(title, message, severity, kwargs)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            return self._send_email(msg)
            
        except Exception as e:
            self.logger.error(f"Failed to send system alert email: {e}")
            return False
    
    def _create_threat_email_body(self, detection: ThreatDetection, additional_context: Optional[Dict[str, Any]]) -> str:
        """Create HTML email body for threat detection."""
        severity_colors = {
            "low": "#28a745",
            "medium": "#ffc107", 
            "high": "#fd7e14",
            "critical": "#dc3545"
        }
        
        color = severity_colors.get(detection.severity.value, "#6c757d")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .content {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #333; }}
                .value {{ color: #666; }}
                .signatures {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; }}
                .ml-predictions {{ background-color: #e9ecef; padding: 10px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚨 Threat Detection Alert</h2>
                <p>Severity: {detection.severity.value.upper()}</p>
            </div>
            
            <div class="content">
                <div class="field">
                    <span class="label">Detection ID:</span>
                    <span class="value">{detection.detection_id}</span>
                </div>
                
                <div class="field">
                    <span class="label">Timestamp:</span>
                    <span class="value">{detection.timestamp.isoformat()}</span>
                </div>
                
                <div class="field">
                    <span class="label">Device ID:</span>
                    <span class="value">{detection.device_id}</span>
                </div>
                
                <div class="field">
                    <span class="label">Threat Score:</span>
                    <span class="value">{detection.threat_score:.3f}</span>
                </div>
                
                <div class="field">
                    <span class="label">Confidence:</span>
                    <span class="value">{detection.confidence:.3f}</span>
                </div>
                
                {f'<div class="field"><span class="label">Attack Category:</span><span class="value">{detection.attack_category.value}</span></div>' if detection.attack_category else ''}
                
                {f'<div class="field"><span class="label">MITRE Tactics:</span><span class="value">{", ".join(detection.mitre_tactics)}</span></div>' if detection.mitre_tactics else ''}
        """
        
        # Add signature matches
        if detection.signature_matches:
            html += '<h3>Signature Matches</h3><div class="signatures">'
            for match in detection.signature_matches:
                html += f'<p><strong>{match.rule_name}</strong> (Score: {match.signature_score:.3f})</p>'
            html += '</div>'
        
        # Add ML predictions
        if detection.ml_predictions:
            html += '<h3>ML Predictions</h3><div class="ml-predictions">'
            for pred in detection.ml_predictions:
                html += f'<p><strong>{pred.model_name}</strong> v{pred.model_version} (Score: {pred.anomaly_score:.3f})</p>'
            html += '</div>'
        
        # Add recommended actions
        if detection.recommended_actions:
            html += '<h3>Recommended Actions</h3><ul>'
            for action in detection.recommended_actions:
                html += f'<li>{action}</li>'
            html += '</ul>'
        
        # Add additional context
        if additional_context:
            html += '<h3>Additional Context</h3><div class="content">'
            for key, value in additional_context.items():
                html += f'<div class="field"><span class="label">{key}:</span><span class="value">{value}</span></div>'
            html += '</div>'
        
        html += """
            </div>
            
            <p><em>This alert was generated by the AI-driven IoT IDS system.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def _create_system_email_body(self, title: str, message: str, severity: str, context: Dict[str, Any]) -> str:
        """Create HTML email body for system alerts."""
        severity_colors = {
            "DEBUG": "#6c757d",
            "INFO": "#17a2b8",
            "WARNING": "#ffc107",
            "ERROR": "#dc3545",
            "CRITICAL": "#721c24"
        }
        
        color = severity_colors.get(severity, "#6c757d")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .content {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; margin-top: 10px; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #333; }}
                .value {{ color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🔧 System Alert</h2>
                <p>Severity: {severity}</p>
            </div>
            
            <div class="content">
                <h3>{title}</h3>
                <p>{message}</p>
                
                <div class="field">
                    <span class="label">Timestamp:</span>
                    <span class="value">{datetime.utcnow().isoformat()}Z</span>
                </div>
        """
        
        # Add context information
        if context:
            html += '<h4>Context Information</h4>'
            for key, value in context.items():
                html += f'<div class="field"><span class="label">{key}:</span><span class="value">{value}</span></div>'
        
        html += """
            </div>
            
            <p><em>This alert was generated by the AI-driven IoT IDS system.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def _send_email(self, msg: MIMEMultipart) -> bool:
        """Send email message via SMTP."""
        try:
            # Create SMTP connection
            if self.config.use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
            
            # Login if credentials provided
            if self.config.username and self.config.password:
                server.login(self.config.username, self.config.password)
            
            # Send email
            text = msg.as_string()
            server.sendmail(self.config.sender_email, self.config.recipients, text)
            server.quit()
            
            self.logger.info(f"Email alert sent to {len(self.config.recipients)} recipients")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return False


class SlackAlerter:
    """Slack alerting functionality."""
    
    def __init__(self, config: SlackConfig):
        """
        Initialize Slack alerter.
        
        Args:
            config: Slack configuration
        """
        if WebClient is None:
            raise IDSError("slack-sdk package is required but not installed")
            
        self.config = config
        self.client = WebClient(token=config.bot_token)
        self.logger = logging.getLogger(__name__)
    
    def send_threat_alert(self, detection: ThreatDetection, additional_context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send threat detection alert to Slack.
        
        Args:
            detection: Threat detection data
            additional_context: Additional context information
            
        Returns:
            True if message was sent successfully
        """
        try:
            # Create Slack message blocks
            blocks = self._create_threat_blocks(detection, additional_context)
            
            # Prepare mentions
            mentions = ""
            if self.config.mention_users:
                mentions = " " + " ".join([f"<@{user}>" for user in self.config.mention_users])
            
            # Send message
            response = self.client.chat_postMessage(
                channel=self.config.channel,
                text=f"🚨 Threat Detected - {detection.severity.value.upper()}{mentions}",
                blocks=blocks,
                username=self.config.username,
                icon_emoji=self.config.icon_emoji
            )
            
            self.logger.info(f"Slack threat alert sent to {self.config.channel}")
            return response["ok"]
            
        except SlackApiError as e:
            self.logger.error(f"Slack API error: {e.response['error']}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send Slack threat alert: {e}")
            return False
    
    def send_system_alert(self, title: str, message: str, severity: str = "INFO", **kwargs) -> bool:
        """
        Send system alert to Slack.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            **kwargs: Additional context
            
        Returns:
            True if message was sent successfully
        """
        try:
            # Create Slack message blocks
            blocks = self._create_system_blocks(title, message, severity, kwargs)
            
            # Send message
            response = self.client.chat_postMessage(
                channel=self.config.channel,
                text=f"🔧 System Alert - {severity}: {title}",
                blocks=blocks,
                username=self.config.username,
                icon_emoji=self.config.icon_emoji
            )
            
            self.logger.info(f"Slack system alert sent to {self.config.channel}")
            return response["ok"]
            
        except SlackApiError as e:
            self.logger.error(f"Slack API error: {e.response['error']}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to send Slack system alert: {e}")
            return False
    
    def _create_threat_blocks(self, detection: ThreatDetection, additional_context: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create Slack message blocks for threat detection."""
        severity_emojis = {
            "low": "🟡",
            "medium": "🟠", 
            "high": "🔴",
            "critical": "🚨"
        }
        
        emoji = severity_emojis.get(detection.severity.value, "⚪")
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Threat Detection Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{detection.severity.value.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat Score:*\n{detection.threat_score:.3f}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Device ID:*\n{detection.device_id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:*\n{detection.confidence:.3f}"
                    }
                ]
            }
        ]
        
        # Add attack category and MITRE tactics if available
        if detection.attack_category or detection.mitre_tactics:
            fields = []
            if detection.attack_category:
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*Attack Category:*\n{detection.attack_category.value}"
                })
            if detection.mitre_tactics:
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*MITRE Tactics:*\n{', '.join(detection.mitre_tactics)}"
                })
            
            blocks.append({
                "type": "section",
                "fields": fields
            })
        
        # Add signature matches
        if detection.signature_matches:
            signature_text = ""
            for match in detection.signature_matches[:3]:  # Limit to first 3
                signature_text += f"• {match.rule_name} (Score: {match.signature_score:.3f})\n"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Signature Matches:*\n{signature_text}"
                }
            })
        
        # Add ML predictions
        if detection.ml_predictions:
            ml_text = ""
            for pred in detection.ml_predictions[:3]:  # Limit to first 3
                ml_text += f"• {pred.model_name} v{pred.model_version} (Score: {pred.anomaly_score:.3f})\n"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*ML Predictions:*\n{ml_text}"
                }
            })
        
        # Add recommended actions
        if detection.recommended_actions:
            actions_text = ""
            for action in detection.recommended_actions[:3]:  # Limit to first 3
                actions_text += f"• {action}\n"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Actions:*\n{actions_text}"
                }
            })
        
        # Add timestamp
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Detection ID: {detection.detection_id} | {detection.timestamp.isoformat()}"
                }
            ]
        })
        
        return blocks
    
    def _create_system_blocks(self, title: str, message: str, severity: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create Slack message blocks for system alerts."""
        severity_emojis = {
            "DEBUG": "🔍",
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨"
        }
        
        emoji = severity_emojis.get(severity, "📋")
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} System Alert"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*\n{message}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Timestamp:*\n{datetime.utcnow().isoformat()}Z"
                    }
                ]
            }
        ]
        
        # Add context information
        if context:
            context_text = ""
            for key, value in list(context.items())[:5]:  # Limit to first 5
                context_text += f"• *{key}:* {value}\n"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Context:*\n{context_text}"
                }
            })
        
        return blocks


class WebhookAlerter:
    """Webhook alerting functionality."""
    
    def __init__(self, config: WebhookConfig):
        """
        Initialize webhook alerter.
        
        Args:
            config: Webhook configuration
        """
        if requests is None:
            raise IDSError("requests package is required but not installed")
            
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configure session with retries
        self.session = requests.Session()
        if HTTPAdapter and Retry:
            retry_strategy = Retry(
                total=config.retry_attempts,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
    
    def send_threat_alert(self, detection: ThreatDetection, additional_context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send threat detection alert via webhook.
        
        Args:
            detection: Threat detection data
            additional_context: Additional context information
            
        Returns:
            True if webhook was called successfully
        """
        try:
            # Prepare payload - use model_dump() for Pydantic models
            signature_matches = []
            for match in detection.signature_matches:
                if hasattr(match, 'model_dump'):
                    signature_matches.append(match.model_dump())
                elif hasattr(match, 'dict'):
                    signature_matches.append(match.dict())
                else:
                    signature_matches.append(asdict(match))
            
            ml_predictions = []
            for pred in detection.ml_predictions:
                if hasattr(pred, 'model_dump'):
                    ml_predictions.append(pred.model_dump())
                elif hasattr(pred, 'dict'):
                    ml_predictions.append(pred.dict())
                else:
                    ml_predictions.append(asdict(pred))
            
            payload = {
                "alert_type": "threat_detection",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "detection": {
                    "detection_id": detection.detection_id,
                    "device_id": detection.device_id,
                    "threat_score": detection.threat_score,
                    "confidence": detection.confidence,
                    "severity": detection.severity.value,
                    "attack_category": detection.attack_category.value if detection.attack_category else None,
                    "mitre_tactics": detection.mitre_tactics,
                    "signature_matches": signature_matches,
                    "ml_predictions": ml_predictions,
                    "recommended_actions": detection.recommended_actions
                }
            }
            
            if additional_context:
                payload["additional_context"] = additional_context
            
            return self._send_webhook(payload)
            
        except Exception as e:
            self.logger.error(f"Failed to send threat alert webhook: {e}")
            return False
    
    def send_system_alert(self, title: str, message: str, severity: str = "INFO", **kwargs) -> bool:
        """
        Send system alert via webhook.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            **kwargs: Additional context
            
        Returns:
            True if webhook was called successfully
        """
        try:
            # Prepare payload
            payload = {
                "alert_type": "system_alert",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "title": title,
                "message": message,
                "severity": severity,
                "context": kwargs
            }
            
            return self._send_webhook(payload)
            
        except Exception as e:
            self.logger.error(f"Failed to send system alert webhook: {e}")
            return False
    
    def _send_webhook(self, payload: Dict[str, Any]) -> bool:
        """Send webhook request."""
        try:
            headers = self.config.headers.copy()
            
            # Add authentication if configured
            if self.config.auth_token:
                headers["Authorization"] = f"Bearer {self.config.auth_token}"
            
            # Send request
            response = self.session.request(
                method=self.config.method,
                url=self.config.url,
                json=payload,
                headers=headers,
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            
            self.logger.info(f"Webhook alert sent to {self.config.url}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Webhook request failed: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending webhook: {e}")
            return False


class KibanaDashboardManager:
    """Kibana dashboard configuration management."""
    
    def __init__(self, config: KibanaConfig):
        """
        Initialize Kibana dashboard manager.
        
        Args:
            config: Kibana configuration
        """
        if requests is None:
            raise IDSError("requests package is required but not installed")
            
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        
        # Configure authentication
        if config.username and config.password:
            self.session.auth = (config.username, config.password)
    
    def create_threat_dashboard(self) -> bool:
        """
        Create threat detection dashboard in Kibana.
        
        Returns:
            True if dashboard was created successfully
        """
        try:
            dashboard_config = {
                "version": "8.0.0",
                "objects": [
                    {
                        "id": "threat-detection-dashboard",
                        "type": "dashboard",
                        "attributes": {
                            "title": "AI-IoT IDS Threat Detection Dashboard",
                            "description": "Real-time threat detection monitoring and analysis",
                            "panelsJSON": json.dumps([
                                {
                                    "version": "8.0.0",
                                    "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
                                    "panelIndex": "1",
                                    "embeddableConfig": {},
                                    "panelRefName": "panel_1"
                                },
                                {
                                    "version": "8.0.0", 
                                    "gridData": {"x": 24, "y": 0, "w": 24, "h": 15},
                                    "panelIndex": "2",
                                    "embeddableConfig": {},
                                    "panelRefName": "panel_2"
                                }
                            ]),
                            "timeRestore": False,
                            "version": 1
                        },
                        "references": [
                            {
                                "name": "panel_1",
                                "type": "visualization",
                                "id": "threat-severity-pie"
                            },
                            {
                                "name": "panel_2", 
                                "type": "visualization",
                                "id": "threat-timeline"
                            }
                        ]
                    }
                ]
            }
            
            url = urljoin(self.config.base_url, f"/s/{self.config.space_id}/api/saved_objects/_import")
            
            response = self.session.post(
                url,
                json=dashboard_config,
                headers={"Content-Type": "application/json", "kbn-xsrf": "true"},
                timeout=self.config.timeout
            )
            
            response.raise_for_status()
            
            self.logger.info("Threat detection dashboard created in Kibana")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create Kibana dashboard: {e}")
            return False
    
    def create_visualizations(self) -> bool:
        """
        Create supporting visualizations for dashboards.
        
        Returns:
            True if visualizations were created successfully
        """
        try:
            # This would contain the actual visualization configurations
            # For brevity, showing structure only
            visualizations = {
                "threat-severity-pie": {
                    "title": "Threats by Severity",
                    "type": "pie",
                    "params": {
                        "grid": {"categoryLines": False, "style": {"color": "#eee"}},
                        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
                        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left"}]
                    }
                },
                "threat-timeline": {
                    "title": "Threat Detection Timeline",
                    "type": "histogram",
                    "params": {
                        "grid": {"categoryLines": False, "style": {"color": "#eee"}},
                        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
                        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left"}]
                    }
                }
            }
            
            # Create each visualization
            for viz_id, viz_config in visualizations.items():
                url = urljoin(self.config.base_url, f"/s/{self.config.space_id}/api/saved_objects/visualization/{viz_id}")
                
                response = self.session.post(
                    url,
                    json={"attributes": viz_config},
                    headers={"Content-Type": "application/json", "kbn-xsrf": "true"},
                    timeout=self.config.timeout
                )
                
                if response.status_code not in [200, 409]:  # 409 = already exists
                    response.raise_for_status()
            
            self.logger.info("Kibana visualizations created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create Kibana visualizations: {e}")
            return False


class AlertingSystem:
    """
    Comprehensive alerting and notification system.
    
    Coordinates multiple alerting channels and manages alert rules.
    """
    
    def __init__(
        self,
        email_config: Optional[EmailConfig] = None,
        slack_config: Optional[SlackConfig] = None,
        webhook_config: Optional[WebhookConfig] = None,
        kibana_config: Optional[KibanaConfig] = None
    ):
        """
        Initialize alerting system.
        
        Args:
            email_config: Email alerting configuration
            slack_config: Slack alerting configuration
            webhook_config: Webhook alerting configuration
            kibana_config: Kibana dashboard configuration
        """
        self.logger = logging.getLogger(__name__)
        self.alert_rules = {}
        self._alert_history = {}
        
        # Initialize alerters
        self.email_alerter = EmailAlerter(email_config) if email_config else None
        self.slack_alerter = SlackAlerter(slack_config) if slack_config else None
        self.webhook_alerter = WebhookAlerter(webhook_config) if webhook_config else None
        self.kibana_manager = KibanaDashboardManager(kibana_config) if kibana_config else None
    
    def add_alert_rule(self, rule: AlertRule):
        """Add alert rule to the system."""
        self.alert_rules[rule.name] = rule
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def remove_alert_rule(self, rule_name: str):
        """Remove alert rule from the system."""
        if rule_name in self.alert_rules:
            del self.alert_rules[rule_name]
            self.logger.info(f"Removed alert rule: {rule_name}")
    
    def should_alert(self, detection: ThreatDetection, rule_name: str = "default") -> bool:
        """
        Check if alert should be sent based on rules and cooldown.
        
        Args:
            detection: Threat detection data
            rule_name: Name of alert rule to check
            
        Returns:
            True if alert should be sent
        """
        rule = self.alert_rules.get(rule_name)
        if not rule or not rule.enabled:
            return False
        
        # Check severity threshold
        severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_levels.get(detection.severity.value, 0) < severity_levels.get(rule.severity_threshold.value, 0):
            return False
        
        # Check threat score threshold
        if detection.threat_score < rule.threat_score_threshold:
            return False
        
        # Check confidence threshold
        if detection.confidence < rule.confidence_threshold:
            return False
        
        # Check cooldown period
        now = datetime.utcnow()
        last_alert_key = f"{rule_name}_{detection.device_id}"
        
        if last_alert_key in self._alert_history:
            last_alert_time = self._alert_history[last_alert_key]
            if now - last_alert_time < timedelta(minutes=rule.cooldown_minutes):
                return False
        
        # Check rate limiting
        hour_key = f"{rule_name}_{now.strftime('%Y-%m-%d-%H')}"
        hour_count = sum(1 for key, time in self._alert_history.items() 
                        if key.startswith(hour_key) and now - time < timedelta(hours=1))
        
        if hour_count >= rule.max_alerts_per_hour:
            return False
        
        return True
    
    def send_threat_alert(
        self,
        detection: ThreatDetection,
        rule_name: str = "default",
        additional_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, bool]:
        """
        Send threat detection alert through all configured channels.
        
        Args:
            detection: Threat detection data
            rule_name: Name of alert rule to use
            additional_context: Additional context information
            
        Returns:
            Dictionary of channel results
        """
        if not self.should_alert(detection, rule_name):
            self.logger.debug(f"Alert suppressed for detection {detection.detection_id}")
            return {}
        
        results = {}
        
        # Update alert history
        now = datetime.utcnow()
        alert_key = f"{rule_name}_{detection.device_id}"
        self._alert_history[alert_key] = now
        
        # Send through all configured channels
        if self.email_alerter:
            results["email"] = self.email_alerter.send_threat_alert(detection, additional_context)
        
        if self.slack_alerter:
            results["slack"] = self.slack_alerter.send_threat_alert(detection, additional_context)
        
        if self.webhook_alerter:
            results["webhook"] = self.webhook_alerter.send_threat_alert(detection, additional_context)
        
        # Log results
        successful_channels = [channel for channel, success in results.items() if success]
        failed_channels = [channel for channel, success in results.items() if not success]
        
        if successful_channels:
            self.logger.info(f"Threat alert sent via: {', '.join(successful_channels)}")
        
        if failed_channels:
            self.logger.warning(f"Failed to send threat alert via: {', '.join(failed_channels)}")
        
        return results
    
    def send_system_alert(
        self,
        title: str,
        message: str,
        severity: str = "INFO",
        **kwargs
    ) -> Dict[str, bool]:
        """
        Send system alert through all configured channels.
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            **kwargs: Additional context
            
        Returns:
            Dictionary of channel results
        """
        results = {}
        
        # Send through all configured channels
        if self.email_alerter:
            results["email"] = self.email_alerter.send_system_alert(title, message, severity, **kwargs)
        
        if self.slack_alerter:
            results["slack"] = self.slack_alerter.send_system_alert(title, message, severity, **kwargs)
        
        if self.webhook_alerter:
            results["webhook"] = self.webhook_alerter.send_system_alert(title, message, severity, **kwargs)
        
        return results
    
    def initialize_dashboards(self) -> bool:
        """
        Initialize Kibana dashboards and visualizations.
        
        Returns:
            True if dashboards were initialized successfully
        """
        if not self.kibana_manager:
            self.logger.warning("Kibana manager not configured")
            return False
        
        try:
            viz_success = self.kibana_manager.create_visualizations()
            dashboard_success = self.kibana_manager.create_threat_dashboard()
            
            return viz_success and dashboard_success
            
        except Exception as e:
            self.logger.error(f"Failed to initialize dashboards: {e}")
            return False
    
    def cleanup_alert_history(self, max_age_hours: int = 24):
        """
        Clean up old alert history entries.
        
        Args:
            max_age_hours: Maximum age of history entries to keep
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        old_keys = [key for key, time in self._alert_history.items() if time < cutoff_time]
        
        for key in old_keys:
            del self._alert_history[key]
        
        if old_keys:
            self.logger.info(f"Cleaned up {len(old_keys)} old alert history entries")