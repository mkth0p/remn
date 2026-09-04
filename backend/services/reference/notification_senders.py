"""
Registrable domains of well-known notification / SaaS relays.

Mails from these senders are flagged ``trusted_sender`` and risk-capped ONLY
when their authentication passes (SPF/DKIM + DMARC, or a passing ARC chain):
a compromised or spoofed account never gets the discount because strong
indicators still score, and failed auth disables the cap entirely.

Why: display-name rules (VIP impersonation, same-name-different-domain) fire on
Teams/SharePoint/GitHub notifications because they legitimately carry a
colleague's name on the vendor's domain.
"""
from __future__ import annotations

NOTIFICATION_SENDERS: dict[str, str] = {
    # Microsoft 365 / Teams / SharePoint
    "microsoft.com": "Microsoft (Teams, 365, security notifications)",
    "sharepointonline.com": "SharePoint Online",
    "microsoftonline.com": "Microsoft 365 sign-in",
    "mail.microsoft": "Microsoft Teams / Viva Engage / Outlook notifications (.microsoft brand TLD)",
    "azure.com": "Microsoft Azure",
    "office.com": "Microsoft Office",
    "windows.com": "Microsoft Windows",
    "skype.com": "Skype",
    "yammer.com": "Viva Engage / Yammer",
    # Google Workspace
    "google.com": "Google (Workspace, Drive, Calendar)",
    "googlemail.com": "Google Mail relay",
    "youtube.com": "YouTube",
    # Dev / project tools
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "atlassian.com": "Atlassian (Jira, Confluence)",
    "atlassian.net": "Atlassian cloud",
    "bitbucket.org": "Bitbucket",
    "slack.com": "Slack",
    "notion.so": "Notion",
    "asana.com": "Asana",
    "trello.com": "Trello",
    "monday.com": "monday.com",
    "figma.com": "Figma",
    "miro.com": "Miro",
    # Meetings
    "zoom.us": "Zoom",
    "webex.com": "Cisco Webex",
    "gotomeeting.com": "GoToMeeting",
    # CRM / ITSM / HR / docs
    "salesforce.com": "Salesforce",
    "servicenow.com": "ServiceNow",
    "service-now.com": "ServiceNow notifications",
    "clickup.com": "ClickUp",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "workday.com": "Workday",
    "successfactors.com": "SAP SuccessFactors",
    "docusign.net": "DocuSign",
    "docusign.com": "DocuSign",
    "adobesign.com": "Adobe Sign",
    # Storage / social / misc corporate SaaS
    "dropbox.com": "Dropbox",
    "box.com": "Box",
    "linkedin.com": "LinkedIn",
    "eventbrite.com": "Eventbrite",
    "surveymonkey.com": "SurveyMonkey",
    "mailchimp.com": "Mailchimp (sender infra)",
    "sendgrid.net": "SendGrid (sender infra)",
    "amazonses.com": "Amazon SES (sender infra)",
    "intuit.com": "Intuit (QuickBooks)",
    "concur.com": "SAP Concur",
}
