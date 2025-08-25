import asyncio
import re
from itertools import product
from PyQt6.QtCore import QObject, pyqtSignal
from playwright.async_api import async_playwright
from threading import Thread

class RaiderManager(QObject):
    """
    Manages a fuzzing job. Supports multiple attack types.
    Runs the fuzzing loop in a separate thread.
    """
    request_completed = pyqtSignal(dict)
    fuzzing_finished = pyqtSignal()
    log_message = pyqtSignal(str)

    def __init__(self, request_template: str, payloads: dict, attack_type: str):
        super().__init__()
        self.request_template = request_template
        self.payloads = payloads  # e.g., {"1": ["p1", "p2"], "2": ["p3"]}
        self.attack_type = attack_type
        self.thread = None
        self._stop_fuzzing = False

    def start(self):
        """Starts the fuzzing job in a background thread."""
        if self.thread and self.thread.is_alive():
            self.log_message.emit("Fuzzing is already in progress.")
            return

        self._stop_fuzzing = False
        self.thread = Thread(target=self._run_fuzzing_job, daemon=True)
        self.thread.start()

    def stop(self):
        """Requests to stop the fuzzing job."""
        self._stop_fuzzing = True
        self.log_message.emit("Fuzzing stop requested.")

    def _run_fuzzing_job(self):
        """The entry point for the background thread."""
        try:
            asyncio.run(self._fuzzing_loop())
        except Exception as e:
            self.log_message.emit(f"Raider error: {e}")
        finally:
            self.fuzzing_finished.emit()

    async def _send_request(self, session, fuzzed_request_str: str):
        """A helper to send a single fuzzed request."""
        # This is a major simplification. A real implementation needs to parse
        # the raw HTTP request string into method, URL, headers, and body.
        url = fuzzed_request_str
        method = "GET"

        try:
            start_time = asyncio.get_event_loop().time()
            response = await session.request.fetch(url, method=method, timeout=10000)
            end_time = asyncio.get_event_loop().time()
            body_bytes = await response.body()
            return {
                "status": response.status,
                "length": len(body_bytes),
                "time_sec": end_time - start_time,
            }
        except Exception as e:
            return {
                "status": -1,
                "length": 0,
                "time_sec": 0,
                "error": str(e)
            }

    async def _fuzzing_loop(self):
        """The main async loop that generates and sends fuzzed requests."""
        self.log_message.emit(f"Starting Raider attack: {self.attack_type}")

        # Find all injection markers, e.g., §1§, §2§
        injection_markers = sorted(list(set(re.findall(r"§\d+§", self.request_template))))
        if not injection_markers:
            self.log_message.emit("No numbered injection markers found (e.g., §1§).")
            return

        async with async_playwright() as p:
            browser = await p.chromium.launch()
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            position = 0

            # --- Sniper Attack ---
            if self.attack_type == 'Sniper':
                # Uses the first payload set for all positions.
                payload_list = self.payloads.get("1", [])
                for marker in injection_markers:
                    for payload in payload_list:
                        if self._stop_fuzzing: break
                        position += 1
                        # Replace only the current marker
                        fuzzed_req = self.request_template.replace(marker, payload)
                        result = await self._send_request(page, fuzzed_req)
                        result.update({"payload": payload, "position": position, "marker": marker})
                        self.request_completed.emit(result)
                    if self._stop_fuzzing: break

            # --- Battering Ram Attack ---
            elif self.attack_type == 'Battering Ram':
                # Uses the first payload set and applies the same payload to all positions.
                payload_list = self.payloads.get("1", [])
                for payload in payload_list:
                    if self._stop_fuzzing: break
                    position += 1
                    fuzzed_req = self.request_template
                    # Replace all markers with the same payload
                    for marker in injection_markers:
                        fuzzed_req = fuzzed_req.replace(marker, payload)
                    result = await self._send_request(page, fuzzed_req)
                    result.update({"payload": payload, "position": position})
                    self.request_completed.emit(result)

            # --- Pitchfork Attack ---
            elif self.attack_type == 'Pitchfork':
                # Requires a payload set for each marker.
                num_requests = min(len(self.payloads.get(str(i+1), [])) for i in range(len(injection_markers)))
                for i in range(num_requests):
                    if self._stop_fuzzing: break
                    position += 1
                    fuzzed_req = self.request_template
                    payload_combo = []
                    for marker_idx, marker in enumerate(injection_markers):
                        payload = self.payloads[str(marker_idx+1)][i]
                        fuzzed_req = fuzzed_req.replace(marker, payload)
                        payload_combo.append(payload)
                    result = await self._send_request(page, fuzzed_req)
                    result.update({"payload": " | ".join(payload_combo), "position": position})
                    self.request_completed.emit(result)

            # --- Cluster Bomb Attack ---
            elif self.attack_type == 'Cluster Bomb':
                # All combinations of all payloads. Dangerous!
                payload_sets = [self.payloads.get(str(i+1), []) for i in range(len(injection_markers))]
                payload_combinations = product(*payload_sets)
                for combo in payload_combinations:
                    if self._stop_fuzzing: break
                    position += 1
                    fuzzed_req = self.request_template
                    for marker, payload in zip(injection_markers, combo):
                        fuzzed_req = fuzzed_req.replace(marker, payload)
                    result = await self._send_request(page, fuzzed_req)
                    result.update({"payload": " | ".join(combo), "position": position})
                    self.request_completed.emit(result)

            await context.close()
        self.log_message.emit("Raider attack finished.")
