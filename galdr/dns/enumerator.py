import asyncio
from threading import Thread
from PyQt6.QtCore import QObject, pyqtSignal

class SubdomainEnumerator(QObject):
    """
    Enumerates subdomains for a given target domain using a wordlist.
    """
    subdomain_found = pyqtSignal(str)
    enumeration_finished = pyqtSignal()
    progress_updated = pyqtSignal(int, int)

    def __init__(self, target_domain: str, wordlist: list[str]):
        super().__init__()
        self.target_domain = target_domain
        self.wordlist = wordlist
        self.thread = None
        self._stop_enumeration = False

    def start(self):
        """Starts the enumeration in a background thread."""
        if self.thread and self.thread.is_alive():
            return

        self._stop_enumeration = False
        self.thread = Thread(target=self._run_enumeration_job, daemon=True)
        self.thread.start()

    def stop(self):
        """Requests to stop the enumeration."""
        self._stop_enumeration = True

    def _run_enumeration_job(self):
        """The entry point for the background thread."""
        try:
            asyncio.run(self._enumeration_loop())
        except Exception as e:
            # A more robust implementation would log this error
            print(f"Subdomain enumeration error: {e}")
        finally:
            self.enumeration_finished.emit()

    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore):
        """Tries to connect to a subdomain to see if it's live."""
        async with semaphore:
            if self._stop_enumeration:
                return

            try:
                # Try connecting to common web ports
                for port in [80, 443]:
                    # We don't need to do anything with the connection, just see if it opens
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(subdomain, port), timeout=3
                    )
                    writer.close()
                    await writer.wait_closed()

                    # If we get here, the connection was successful
                    self.subdomain_found.emit(subdomain)
                    return # Found it, no need to check other ports
            except (asyncio.TimeoutError, OSError):
                # This is expected for non-existent subdomains
                pass
            except Exception:
                # Other unexpected errors
                pass

    async def _enumeration_loop(self):
        """The main async loop that checks subdomains."""
        semaphore = asyncio.Semaphore(100) # Limit concurrent checks
        total = len(self.wordlist)
        tasks = []

        for i, word in enumerate(self.wordlist):
            if self._stop_enumeration:
                break

            subdomain = f"{word}.{self.target_domain}"
            task = asyncio.create_task(self._check_subdomain(subdomain, semaphore))
            tasks.append(task)

            # Update progress every 10 tasks to avoid excessive signal emission
            if i % 10 == 0:
                self.progress_updated.emit(i + 1, total)

        await asyncio.gather(*tasks, return_exceptions=True)
        self.progress_updated.emit(total, total)
