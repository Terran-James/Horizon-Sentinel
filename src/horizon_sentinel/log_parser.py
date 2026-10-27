def parse_failed_ssh_login(log_line):
    """Extract the source IP from a failed SSH login entry."""

    if "Failed password" not in log_line:
        return None

    parts = log_line.split()

    if "from" not in parts:
        return None

    from_index = parts.index("from")

    if from_index + 1 >= len(parts):
        return None

    source_ip = parts[from_index + 1]

    return source_ip

def read_failed_ssh_log(file_path):
    """Read a log file and collect source IPs from failed SSH logins."""
    
    failed_logins = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            source_ip = parse_failed_ssh_login(line)

            if source_ip is not None:
                failed_logins.append(source_ip)

    return failed_logins

from datetime import datetime


def parse_failed_ssh_event(log_line):
    """Extract the timestamp and source IP from a failed SSH login."""

    source_ip = parse_failed_ssh_login(log_line)

    if source_ip is None:
        return None

    parts = log_line.split()

    timestamp_text = " ".join(parts[:3])

    timestamp = datetime.strptime(
        f"{timestamp_text} 2026",
        "%b %d %H:%M:%S %Y",
    )

    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
    }

def read_failed_ssh_events(file_path):
    """Read a log file and collect timestamped failed SSH login events."""

    events = []

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_failed_ssh_event(line)

            if event is not None:
                events.append(event)

    return events