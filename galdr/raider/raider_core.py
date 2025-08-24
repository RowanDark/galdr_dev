import asyncio
from PyQt6.QtCore import QObject, pyqtSignal
from playwright.async_api import async_playwright
from threading import Thread

class RaiderManager(QObject):
    """
    Manages a fuzzing job (e.g., a "sniper" attack).
    Runs the fuzzing loop in a separate thread.
    """
    request_completed = pyqtSignal(dict)
    fuzzing_finished = pyqtSignal()
    log_message = pyqtSignal(str)

    def __init__(self, request_template: str, injection_points: list, payloads: list):
        super().__init__()
        self.request_template = request_template
        self.injection_points = injection_points
        self.payloads = payloads
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
            self.log_message.emit(f"Fuzzing error: {e}")
        finally:
            self.fuzzing_finished.emit()

    async def _fuzzing_loop(self):
        """The main async loop that sends fuzzed requests."""
        self.log_message.emit("Starting Raider attack...")

        async with async_playwright() as p:
            browser = await p.chromium.launch()

            for point in self.injection_points:
                if self._stop_fuzzing: break

                for i, payload in enumerate(self.payloads):
                    if self._stop_fuzzing: break

                    # Prepare the request
                    # For now, we assume a simple string replacement on the whole template
                    # A more advanced version would handle headers/body/URL separately
                    fuzzed_request_str = self.request_template.replace(point, payload)

                    # This is a simplified parsing. A real implementation needs to parse
                    # the full raw HTTP request string.
                    # For now, we'll assume the template is just a URL for simplicity.
                    url = fuzzed_request_str # Simplified assumption
                    method = "GET" # Simplified assumption

                    context = await browser.new_context(ignore_https_errors=True)
                    page = await context.new_page()

                    try:
                        start_time = asyncio.get_event_loop().time()
                        response = await page.request.fetch(url, method=method, timeout=10000)
                        end_time = asyncio.get_event_loop().time()
                        body_bytes = await response.body()

                        result = {
                            "payload": payload,
                            "status": response.status,
                            "length": len(body_bytes),
                            "time_sec": end_time - start_time,
                            "position": i + 1,
                        }
                        self.request_completed.emit(result)

                    except Exception as e:
                        result = {
                            "payload": payload,
                            "status": -1,
                            "length": 0,
                            "time_sec": 0,
                            "position": i + 1,
                            "error": str(e)
                        }
                        self.request_completed.emit(result)
                    finally:
                        await context.close()

        self.log_message.emit("Raider attack finished.")
