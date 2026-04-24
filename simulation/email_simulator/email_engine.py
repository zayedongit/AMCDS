"""
Email Engine - Simulates SMTP-like email flow between enterprise users.
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EmailEvent:
    tick: int
    timestamp: float
    event_type: str  # "send", "receive", "read", "delete", "forward"
    sender_id: str
    sender_email: str
    recipients: list[str]
    subject: str
    body_length: int
    has_attachment: bool = False
    attachment_name: str | None = None
    attachment_size: int = 0
    is_external: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    flags: dict[str, bool] = field(default_factory=dict)  # "suspicious", "phishing", etc.


SUBJECT_TEMPLATES = [
    "Q{q} {dept} Report", "Meeting: {topic}", "RE: {topic}", "FW: {topic}",
    "Action Required: {topic}", "Update on {topic}", "Weekly {dept} Sync",
    "Invoice #{num}", "Project {topic} Status", "Request for {topic}",
]

TOPICS = ["budget review", "system upgrade", "policy update", "team standup",
          "client proposal", "security audit", "performance review", "vendor onboarding"]

ATTACHMENT_TYPES = [
    ("report.xlsx", 50000), ("presentation.pptx", 2000000), ("document.docx", 100000),
    ("data.csv", 30000), ("notes.pdf", 75000), ("image.png", 500000),
]


class EmailEngine:
    """Simulates realistic enterprise email traffic."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self._rng = random.Random(seed)
        self._email_counter = 0
        self._mailboxes: dict[str, list[dict]] = {}  # user_id -> inbox items

    def initialize_mailboxes(self, user_ids: list[str]) -> None:
        for uid in user_ids:
            self._mailboxes[uid] = []

    def generate_send_event(self, tick: int, timestamp: float, sender_id: str,
                            sender_email: str, recipient_ids: list[str],
                            department: str = "IT") -> EmailEvent:
        self._email_counter += 1
        subject = self._generate_subject(department)
        has_attach = self._rng.random() < 0.15
        attach_name, attach_size = None, 0
        if has_attach:
            attach_name, attach_size = self._rng.choice(ATTACHMENT_TYPES)

        evt = EmailEvent(
            tick=tick, timestamp=timestamp, event_type="send",
            sender_id=sender_id, sender_email=sender_email,
            recipients=[f"{rid}@amcds-corp.sim" for rid in recipient_ids],
            subject=subject, body_length=self._rng.randint(50, 2000),
            has_attachment=has_attach, attachment_name=attach_name, attachment_size=attach_size,
            headers={"Message-ID": f"<msg-{self._email_counter:08d}@amcds-corp.sim>", "X-Mailer": "AMCDSMail/1.0"},
        )

        # Deliver to recipients' mailboxes
        for rid in recipient_ids:
            if rid in self._mailboxes:
                self._mailboxes[rid].append({"from": sender_email, "subject": subject, "time": timestamp, "read": False})

        return evt

    def generate_read_event(self, tick: int, timestamp: float, user_id: str,
                            user_email: str) -> EmailEvent | None:
        mailbox = self._mailboxes.get(user_id, [])
        unread = [m for m in mailbox if not m["read"]]
        if not unread:
            return None
        msg = self._rng.choice(unread)
        msg["read"] = True
        return EmailEvent(
            tick=tick, timestamp=timestamp, event_type="read",
            sender_id=user_id, sender_email=user_email, recipients=[],
            subject=msg["subject"], body_length=0,
        )

    def _generate_subject(self, dept: str) -> str:
        template = self._rng.choice(SUBJECT_TEMPLATES)
        return template.format(
            q=self._rng.randint(1, 4), dept=dept,
            topic=self._rng.choice(TOPICS), num=self._rng.randint(1000, 9999),
        )
