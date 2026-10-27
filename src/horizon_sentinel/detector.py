from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

def detect_repeated_failures(failed_logins, threshold=5):
    """Identify source IPs with failures at or above the threhold."""

    failure_counts = Counter(failed_logins)
    alerts = {}

    for soucrce_ip, count in failure_counts.items():
        if count >= threshold:
            alerts[soucrce_ip] = count

    return alerts

def detect_failures_within_window(
        events,
        threshold=5,
        window_minutes=5,
):
    """Detect source IPs reaching the failure threshold within a time window."""

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than 0")

    window = timedelta(minutes=window_minutes)
    events_by_ip = defaultdict(list)

    for event in events:
        event_time = datetime.strptime(
            event["timestamp"],
            "%Y-%m-%d %H:%M:%S",
        )
        events_by_ip[event["source_ip"]].append(event_time)

    alerts = {}

    for source_ip, timestamps in events_by_ip.items():
        timestamps.sort()
        window_events = deque()

        for event_time in timestamps:
            while (
                window_events
                and event_time - window_events[0] >= window
            ):
                window_events.popleft()

            window_events.append(event_time)

            if len(window_events) >= threshold:
                alerts[source_ip] = len(window_events)
                break

    return alerts