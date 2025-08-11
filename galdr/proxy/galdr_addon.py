import json
import os
import time
from mitmproxy import ctx, http

# Define communication files in a temporary directory
# This assumes a standard temp dir, making it more portable.
from tempfile import gettempdir
TEMP_DIR = gettempdir()
EVENTS_FILE = os.path.join(TEMP_DIR, "galdr_events.log")
COMMAND_FILE = os.path.join(TEMP_DIR, "galdr_commands.log")

class GaldrGUIAddon:
    def __init__(self):
        self.intercept_requests = False
        self.intercept_responses = False
        # Clear communication files on startup
        with open(EVENTS_FILE, "w") as f:
            f.write("")
        with open(COMMAND_FILE, "w") as f:
            f.write("")
        print("Galdr Addon Initialized.")

    def log_event(self, event_type, data):
        """Writes an event to the events file for the GUI to read."""
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps({"type": event_type, "data": data}) + "\n")

    def request(self, flow: http.HTTPFlow):
        """Called for every request."""
        # For now, we only care about interception. Logging will be handled by the response.
        if self.intercept_requests:
            flow.intercept()

            request_data = {
                'flow_id': flow.id,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': flow.request.get_text(strict=False)
            }
            self.log_event("request_intercepted", request_data)

            # Block and wait for a command from the GUI
            command = self.wait_for_command(flow.id)

            if command:
                if command['action'] == 'drop':
                    flow.kill()
                elif command['action'] == 'forward':
                    # Apply modifications from GUI
                    modified_data = command['data']['request']
                    flow.request.text = modified_data['body']
                    flow.request.headers.clear()
                    for k, v in modified_data['headers'].items():
                        flow.request.headers[k] = v
                    flow.resume()
            else:
                flow.resume() # Failsafe

    def response(self, flow: http.HTTPFlow):
        """Called for every response."""
        # Always log the completed flow
        log_data = {
            'flow_id': flow.id,
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'status_code': flow.response.status_code,
            'headers': dict(flow.request.headers), # Log request headers
            'body': flow.request.get_text(strict=False) # Log request body
        }
        self.log_event("flow_log", log_data)

        # TODO: Implement response interception logic here

    def wait_for_command(self, flow_id):
        """
        Polls the command file until a command for the given flow_id is found.
        """
        while True:
            try:
                with open(COMMAND_FILE, "r+") as f:
                    lines = f.readlines()
                    # Find command for our flow_id
                    for i, line in enumerate(lines):
                        if line.strip():
                            cmd = json.loads(line)
                            if cmd.get("flow_id") == flow_id:
                                # Found command, remove it from file and return
                                del lines[i]
                                f.seek(0)
                                f.truncate()
                                f.writelines(lines)
                                return cmd
            except (IOError, json.JSONDecodeError):
                pass # Ignore errors and retry
            time.sleep(0.1) # Poll every 100ms

addons = [GaldrGUIAddon()]
