"""
event_sender.py
HTTP client that sends structured security events to the Profiler REST API.
Used by both server_monitor and decoy_logger.
"""

import requests
import logging
import json
import time

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds between retries


class EventSender:
    """
    Sends security events to the Deception Profiling Engine REST API.
    Handles retries and connection errors gracefully.
    """

    def __init__(self, config: dict):
        profiler = config["profiler"]
        profiler_ip = config["network"]["profiler_ip"]
        self.profiler_url = (
            f"http://{profiler_ip}:{profiler['port']}/api/event"
        )
        self.api_key = profiler["api_key"]
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        logger.info(f"EventSender initialized. Target: {self.profiler_url}")

    def send_event(self, event: dict, retries: int = MAX_RETRIES) -> dict | None:
        """
        POST an event to the profiler API.

        Args:
            event: dict with src_ip, event_type, severity, timestamp, details, source
            retries: number of retry attempts on failure

        Returns:
            Profiler response dict on success, None on failure
        """
        for attempt in range(retries):
            try:
                response = self.session.post(
                    self.profiler_url,
                    json=event,
                    timeout=5
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.debug(
                        f"Event sent successfully: {event.get('event_type')} "
                        f"from {event.get('src_ip')} | "
                        f"Score: {result.get('new_score')}"
                    )
                    return result

                elif response.status_code == 401:
                    logger.error("Authentication failed: check API key in config.json")
                    return None  # No point retrying auth failures

                else:
                    logger.warning(
                        f"Profiler returned {response.status_code}: {response.text[:200]}"
                    )

            except requests.exceptions.ConnectionError:
                logger.warning(
                    f"Cannot connect to profiler at {self.profiler_url} "
                    f"(attempt {attempt + 1}/{retries})"
                )
            except requests.exceptions.Timeout:
                logger.warning(
                    f"Request timeout to profiler (attempt {attempt + 1}/{retries})"
                )
            except Exception as e:
                logger.error(f"Unexpected error sending event: {e}")
                return None

            if attempt < retries - 1:
                time.sleep(RETRY_DELAY)

        logger.error(f"Failed to send event after {retries} attempts: {event}")
        return None

    def send_batch(self, events: list) -> list:
        """Send a list of events, returning results for each."""
        results = []
        for event in events:
            result = self.send_event(event)
            results.append(result)
        return results

    def test_connection(self) -> bool:
        """Verify connectivity to the profiler service."""
        health_url = self.profiler_url.replace("/api/event", "/api/health")
        try:
            resp = requests.get(health_url, timeout=3)
            if resp.status_code == 200:
                logger.info(f"Profiler health check OK: {health_url}")
                return True
        except Exception as e:
            logger.error(f"Profiler health check failed: {e}")
        return False
