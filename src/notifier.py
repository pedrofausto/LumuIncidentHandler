import smtplib
import logging
import os
from datetime import datetime
from email.message import EmailMessage
from typing import List
from jinja2 import Environment, select_autoescape, FileSystemLoader
from .config import get_settings
from .analyzer import IncidentEvent

logger = logging.getLogger(__name__)

SEVERITY_STYLE = {
    "Critical":    ("#c0392b", "192,57,43"),
    "High":        ("#e67e22", "230,126,34"),
    "Medium":      ("#f1c40f", "241,196,15"),
    "Low":         ("#3498db", "52,152,219"),
    "Information": ("#7f8c8d", "127,140,141"),
}

def _fmt_ts(iso: str) -> str:
    """Convert ISO 8601 to DD/MM/YYYY HH:MM:SS. Returns '—' on failure."""
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return iso[:19].replace("T", " ")


class Notifier:
    def __init__(self):
        self.settings = get_settings()
        # Secure template loading using absolute path (Finding 4)
        template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
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
            template = self.env.get_template("lumu_alert_mockup.html")
        except Exception as te:
            logger.error(f"Failed to load template: {te}")
            return False

        for event in events:
            logger.info(f"Sending incident alert: '{event.title}' for tenant '{tenant_name}'")

            try:
                now        = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                monitor_id = f"LUMU-INC-{tenant_uuid[:4].upper()}"

                sev_key = event.severity.capitalize() if event.severity else "High"
                if sev_key not in SEVERITY_STYLE:
                    sev_key = "High"
                stripe_color, severity_rgb = SEVERITY_STYLE[sev_key]

                # ── Render with Jinja2 ────────────────────────────────────────
                render_context = {
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
                    "fmt_ts": _fmt_ts  # Pass function for use in template
                }

                final_html = template.render(**render_context)

                # ── SMTP ─────────────────────────────────────────────────────
                msg = EmailMessage()
                msg['Subject'] = f"[Lumu] {sev_key} — {event.adversary_type}: {event.title[:60]}"
                msg['From']    = self.settings.smtp_from_email
                msg['To']      = self.settings.alert_to_email
                msg.set_content("Habilite a visualização de HTML para ver este alerta.")
                msg.add_alternative(final_html, subtype='html')

                if self.settings.smtp_port == 465:
                    server_cls, starttls = smtplib.SMTP_SSL, False
                else:
                    server_cls, starttls = smtplib.SMTP, True

                with server_cls(self.settings.smtp_host, self.settings.smtp_port, timeout=15) as srv:
                    if starttls:
                        srv.starttls()
                    srv.login(self.settings.smtp_user, self.settings.smtp_pass.get_secret_value())
                    srv.send_message(msg)

                logger.info(f"Alert email dispatched for incident {event.incident_uuid}")

            except Exception as e:
                logger.error(f"Failed to dispatch alert for incident {event.incident_uuid}: {e}")
                all_success = False
        
        return all_success
