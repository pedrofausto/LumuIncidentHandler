import smtplib
import logging
import os
from datetime import datetime
from email.message import EmailMessage
from typing import List
from jinja2 import Environment, select_autoescape, FileSystemLoader
import dateutil.parser
from .config import get_settings
from .analyzer import IncidentEvent
from .l10n import ENGLISH_MAP

logger = logging.getLogger(__name__)

SEVERITY_STYLE = {
    "Critical":    ("#c0392b", "192,57,43"),
    "High":        ("#e67e22", "230,126,34"),
    "Medium":      ("#f1c40f", "241,196,15"),
    "Low":         ("#3498db", "52,152,219"),
    "Information": ("#7f8c8d", "127,140,141"),
}

def _fmt_ts(iso: str) -> str:
    """Convert ISO 8601 to Oct 01, 2025 - 10:44:34. Returns '—' on failure."""
    if not iso:
        return "—"
    try:
        dt = dateutil.parser.parse(iso)
        return dt.strftime("%b %d, %Y - %H:%M:%S")
    except Exception:
        return iso[:19].replace("T", " ")


class Notifier:
    def __init__(self):
        self.settings = get_settings()
        # Secure template loading using absolute path (Finding 4)
        template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def send_incident_alert(self, events: List[IncidentEvent], tenant_uuid: str, tenant_name: str = "Unknown") -> bool:
        if not events:
            return False

        all_success = True
        # Load template by name from the secure loader
        try:
            template = self.env.get_template("lumu_incident_alert.html")
        except Exception as te:
            logger.error(f"Failed to load template: {te}")
            return False

        for event in events:
            logger.info(f"Sending incident alert: '{event.title}' for tenant '{tenant_name}'")

            try:
                now        = datetime.now().strftime("%b %d, %Y - %H:%M:%S")
                monitor_id = f"LUMU-INC-{tenant_uuid[:4].upper()}"

                sev_key = event.severity.capitalize() if event.severity else "High"
                if sev_key not in SEVERITY_STYLE:
                    sev_key = "High"
                stripe_color, severity_rgb = SEVERITY_STYLE[sev_key]

                # ── Render with Jinja2 ────────────────────────────────────────
                render_context = {
                    "l10n": ENGLISH_MAP,
                    "date_time": now,
                    "monitor_id": monitor_id,
                    "tenant_name": tenant_name,
                    "event": event,
                    "sev_key": sev_key,
                    "stripe_color": stripe_color,
                    "severity_rgb": severity_rgb,
                    "first_contact": _fmt_ts(event.first_contact),
                    "last_contact": _fmt_ts(event.last_contact),
                    "summary_first_contact": _fmt_ts(event.first_contact),
                    "sighting_count": str(event.stix_sighting.count if event.stix_sighting else "—"),
                    "tlp": event.tlp,
                    "fmt_ts": _fmt_ts,
                    "incident_summary": event.details or event.title,
                    "incident_count": 1,
                    "total_endpoints": event.endpoints_affected,
                    "dissemination_latency": event.dissemination_latency or "—",
                    "mtt_dissemination": event.dissemination_latency or "—",
                    "mtt_response": event.mtt_response or "—",
                    "mtt_resolution": event.mtt_resolution or "—",
                    "triggered_integrations": event.triggered_integrations,
                    "stix_indicators": event.stix_indicators,
                    "affected_endpoints": event.affected_endpoints,
                    "incident_rows": self._render_incident_row(event, stripe_color, sev_key)
                }

                final_html = template.render(**render_context)

                # ── SMTP ─────────────────────────────────────────────────────
                msg = EmailMessage()
                msg['Subject'] = f"[Lumu] {sev_key} — {event.adversary_type}: {event.title[:60]}"
                msg['From']    = self.settings.smtp_from_email
                msg['To']      = self.settings.alert_to_email
                msg.set_content("Please enable HTML view to see this alert.")
                msg.add_alternative(final_html, subtype='html')

                if self.settings.smtp_port == 465:
                    server_cls, starttls = smtplib.SMTP_SSL, False
                else:
                    server_cls, starttls = smtplib.SMTP, True

                logger.debug(f"Connecting to SMTP {self.settings.smtp_host}:{self.settings.smtp_port} (SSL: {not starttls})...")
                with server_cls(self.settings.smtp_host, self.settings.smtp_port, timeout=30) as srv:
                    if starttls:
                        logger.debug("Starting TLS...")
                        srv.starttls()
                    
                    logger.debug(f"Logging in as {self.settings.smtp_user}...")
                    srv.login(self.settings.smtp_user, self.settings.smtp_pass.get_secret_value())
                    
                    logger.debug("Sending message...")
                    srv.send_message(msg)

                logger.info(f"Alert email dispatched for incident {event.incident_uuid}")

            except Exception as e:
                logger.error(f"Failed to dispatch alert for incident {event.incident_uuid}: {e}")
                all_success = False
        
        return all_success

    def _render_incident_row(self, event: IncidentEvent, stripe_color: str, sev_key: str) -> str:
        """Renders a single incident row for the HTML table."""
        indicators_html = ""
        if event.stix_indicators:
            # Limit to 3 for conciseness in the row
            for ind in event.stix_indicators[:3]:
                indicators_html += f'<div style="color:#79c0ff;font-size:9px;margin-bottom:2px">{ind.name}</div>'
            if len(event.stix_indicators) > 3:
                indicators_html += f'<div style="color:#5b84b8;font-size:8px">+ {len(event.stix_indicators) - 3} more</div>'
        else:
            indicators_html = '<div style="color:#5b84b8;font-size:9px">—</div>'

        workstations_html = ""
        if event.affected_endpoints:
            # Limit to 3 for conciseness in the row
            for ws in event.affected_endpoints[:3]:
                workstations_html += f'<div style="color:#c6dcff;font-size:9px">{ws.name}</div>'
            if len(event.affected_endpoints) > 3:
                workstations_html += f'<div style="color:#8aa3c7;font-size:8px;margin-top:2px">+ {len(event.affected_endpoints) - 3} more</div>'
        else:
            workstations_html = f'<div style="color:#c6dcff;font-size:10px">{event.endpoints_affected}</div>'

        first_contact_fmt = _fmt_ts(event.first_contact)

        return f"""
        <tr style="border-bottom:1px solid #1c2a44">
          <td style="padding:10px 5px;vertical-align:top">
            <span style="background-color:{stripe_color};color:#fff;font-size:8px;padding:2px 5px;border-radius:3px;text-transform:uppercase;font-weight:700">{sev_key}</span>
          </td>
          <td style="padding:10px 5px;vertical-align:top">
            <div style="color:#e6f1ff;font-size:11px;font-weight:600">{event.title}</div>
            <div style="color:#5b84b8;font-size:9px;margin-top:3px">ID: {event.incident_uuid[:8]}...</div>
            <div style="color:#8aa3c7;font-size:8px;margin-top:5px">First Contact: {first_contact_fmt}</div>
          </td>
          <td style="padding:10px 5px;vertical-align:top">
            <div style="color:#c6dcff;font-size:10px">{event.adversary_type}</div>
            <div style="color:#5b84b8;font-size:9px;margin-top:3px">{event.adversary_id}</div>
          </td>
          <td style="padding:10px 5px;vertical-align:top">
            {workstations_html}
          </td>
          <td style="padding:10px 5px;vertical-align:top">
            {indicators_html}
          </td>
        </tr>
        """
