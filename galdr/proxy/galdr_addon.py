import json
import os
import time
from mitmproxy import ctx, http

# Define communication files in a temporary directory
from tempfile import gettempdir
TEMP_DIR = gettempdir()
EVENTS_FILE = os.path.join(TEMP_DIR, "galdr_events.log")
COMMAND_FILE = os.path.join(TEMP_DIR, "galdr_commands.log")
STATE_FILE = os.path.join(TEMP_DIR, "galdr_state.json")

class GaldrGUIAddon:
    def __init__(self):
        self.state = {'intercept_requests': False, 'intercept_responses': False}
        # Clear communication files on startup
        with open(EVENTS_FILE, "w") as f: f.write("")
        with open(COMMAND_FILE, "w") as f: f.write("")
        self.update_state(self.state) # Create state file with defaults
        print("Galdr Addon Initialized.")

    def update_state(self, new_state=None):
        """Reads state from the state file, or writes it if new_state is provided."""
        if new_state:
            with open(STATE_FILE, "w") as f:
                json.dump(new_state, f)
            self.state = new_state
        else:
            try:
                with open(STATE_FILE, "r") as f:
                    self.state = json.load(f)
            except (IOError, json.JSONDecodeError):
                # If file doesn't exist or is invalid, use defaults
                pass

    def log_event(self, event_type, data):
        """Writes an event to the events file for the GUI to read."""
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps({"type": event_type, "data": data}) + "\n")

    def request(self, flow: http.HTTPFlow):
        """Called for every request."""
        self.update_state() # Read the latest state from the GUI
        if self.state.get('intercept_requests', False):
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

        # Handle response interception
        self.update_state()
        if self.state.get('intercept_responses', False):
            flow.intercept()

            response_data = {
                'flow_id': flow.id,
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': flow.response.get_text(strict=False)
            }
            self.log_event("response_intercepted", response_data)

            # Block and wait for a command from the GUI
            command = self.wait_for_command(flow.id)

            if command:
                if command['action'] == 'drop':
                    flow.kill()
                elif command['action'] == 'forward':
                    # Apply modifications from GUI if they exist
                    if 'data' in command and 'response' in command['data']:
                        modified_data = command['data']['response']
                        flow.response.text = modified_data.get('body', flow.response.text)
                        flow.response.status_code = modified_data.get('status_code', flow.response.status_code)
                        if 'headers' in modified_data:
                            flow.response.headers.clear()
                            for k, v in modified_data['headers'].items():
                                flow.response.headers[k] = v
                    flow.resume()
            else:
                flow.resume() # Failsafe

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
