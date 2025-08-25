import asyncio
import re
from itertools import product
from PyQt6.QtCore import QObject, pyqtSignal
from playwright.async_api import async_playwright
from threading import Thread

from galdr.utils.http_parser import parse_raw_http_request

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
        self.payloads = payloads
        self.attack_type = attack_type
        self.thread = None
        self._stop_fuzzing = False

    def start(self):
        self._stop_fuzzing = False
        self.thread = Thread(target=self._run_fuzzing_job, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_fuzzing = True
        self.log_message.emit("Fuzzing stop requested.")

    def _run_fuzzing_job(self):
        try:
            asyncio.run(self._fuzzing_loop())
        except Exception as e:
            self.log_message.emit(f"Raider error: {e}")
        finally:
            self.fuzzing_finished.emit()

    async def _send_fuzzed_request(self, session, fuzzed_template: str):
        """Parses a fuzzed request string and sends it."""
        parsed_request = parse_raw_http_request(fuzzed_template)
        if not parsed_request:
            return {"status": -1, "length": 0, "error": "HTTP parsing error"}

        # Determine scheme (a bit simplistic)
        scheme = 'https' if '443' in parsed_request['host'] else 'http'
        url = f"{scheme}://{parsed_request['host']}{parsed_request['path']}"

        try:
            start_time = asyncio.get_event_loop().time()
            response = await session.request.fetch(
                url,
                method=parsed_request['method'],
                headers=parsed_request['headers'],
                data=parsed_request['body'].encode() if parsed_request['body'] else None,
                timeout=10000
            )
            end_time = asyncio.get_event_loop().time()
            body_bytes = await response.body()
            return {
                "status": response.status,
                "length": len(body_bytes),
                "time_sec": end_time - start_time,
            }
        except Exception as e:
            return {"status": -1, "length": 0, "error": str(e), "time_sec": 0}

    def _apply_payloads(self, template, markers, payload_combo):
        """Helper to apply a combination of payloads to a template."""
        fuzzed_req = template
        for marker, payload in zip(markers, payload_combo):
            fuzzed_req = fuzzed_req.replace(marker, str(payload))
        return fuzzed_req

    async def _fuzzing_loop(self):
        self.log_message.emit(f"Starting Raider attack: {self.attack_type}")

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
                payload_list = self.payloads.get("1", [])
                for marker in injection_markers:
                    for payload in payload_list:
                        if self._stop_fuzzing: break
                        position += 1
                        fuzzed_req = self.request_template.replace(marker, payload)
                        result = await self._send_fuzzed_request(page, fuzzed_req)
                        result.update({"payload": payload, "position": position})
                        self.request_completed.emit(result)
                    if self._stop_fuzzing: break

            # --- Battering Ram Attack ---
            elif self.attack_type == 'Battering Ram':
                payload_list = self.payloads.get("1", [])
                for payload in payload_list:
                    if self._stop_fuzzing: break
                    position += 1
                    fuzzed_req = self._apply_payloads(self.request_template, injection_markers, [payload] * len(injection_markers))
                    result = await self._send_fuzzed_request(page, fuzzed_req)
                    result.update({"payload": payload, "position": position})
                    self.request_completed.emit(result)

            # --- Pitchfork Attack ---
            elif self.attack_type == 'Pitchfork':
                num_requests = min(len(self.payloads.get(str(i+1), [])) for i in range(len(injection_markers)))
                for i in range(num_requests):
                    if self._stop_fuzzing: break
                    position += 1
                    payload_combo = [self.payloads[str(marker_idx+1)][i] for marker_idx in range(len(injection_markers))]
                    fuzzed_req = self._apply_payloads(self.request_template, injection_markers, payload_combo)
                    result = await self._send_fuzzed_request(page, fuzzed_req)
                    result.update({"payload": " | ".join(map(str, payload_combo)), "position": position})
                    self.request_completed.emit(result)

            # --- Cluster Bomb Attack ---
            elif self.attack_type == 'Cluster Bomb':
                payload_sets = [self.payloads.get(str(i+1), []) for i in range(len(injection_markers))]
                payload_combinations = product(*payload_sets)
                for combo in payload_combinations:
                    if self._stop_fuzzing: break
                    position += 1
                    fuzzed_req = self._apply_payloads(self.request_template, injection_markers, combo)
                    result = await self._send_fuzzed_request(page, fuzzed_req)
                    result.update({"payload": " | ".join(map(str, combo)), "position": position})
                    self.request_completed.emit(result)

            await context.close()
        self.log_message.emit("Raider attack finished.")
