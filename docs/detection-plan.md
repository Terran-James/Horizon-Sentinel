# Detection Plan: Repeated SSH Login Failures

## Objective

Identify potentially suspicious SSH authentication activity by detecting repeated failed login attempts from a single source IP address.

## Log Source

Linux authentication logs, such as `/var/log/auth.log` on Debian-based systems.

## Detection Logic

Generate an alert when a single source IP address produces **5 or more failed SSH login attempts within a rolling 5-minute window**.

## Required Event Information

Each parsed event should contain:

- Timestamp
- Source IP address
- Authentication result
- Relevant username, when available

## Alert Information

Each alert should include:

- Source IP address
- Number of failed attempts
- Start and end timestamps for the detected activity
- A short explanation of why the activity was flagged

## Investigation Notes

Repeated failed logins may indicate password guessing, a misconfigured service, or a user entering incorrect credentials. An alert is a lead for investigation, not proof of malicious activity.

## Initial Test Cases

1. Fewer than 5 failures from one IP should not trigger an alert.
2. Five failures from one IP within 5 minutes should trigger an alert.
3. Failures from different IP addresses should be counted separately.
4. Failures spread beyond the 5-minute window should not trigger an alert.
5. Successful logins should not count toward the failed-attempt threshold.