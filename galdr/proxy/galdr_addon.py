import asyncio
import json
from mitmproxy import ctx, http
from aiohttp import web, ClientSession

class GaldrGUIAddon:
    def __init__(self):
        self.state = {'intercept_requests': False, 'intercept_responses': False}
        self.pending_commands: dict[str, asyncio.Future] = {}
        self.web_server_task = None
        self.client_session = None
        self.event_port = 8082  # Default, will be overridden
        self.command_port = 8083 # Default, will be overridden
        print("Galdr Addon Initializing...")

    def load(self, loader):
        """Called by mitmproxy to configure the addon."""
        loader.add_option(
            name="galdr_event_port",
            typespec=int,
            default=8082,
            help="Port for Galdr GUI to listen for events",
        )
        loader.add_option(
            name="galdr_command_port",
            typespec=int,
            default=8083,
            help="Port for Galdr addon to listen for commands",
        )

    def configure(self, updates):
        """Called when options are updated."""
        self.event_port = ctx.options.galdr_event_port
        self.command_port = ctx.options.galdr_command_port

    def running(self):
        """Called when the proxy is running."""
        # Create a persistent client session
        self.client_session = ClientSession()
        # Start the command server as a background task
        self.web_server_task = asyncio.create_task(self.run_command_server())
        print("Galdr Addon Running and Command Server started.")

    async def done(self):
        """Called when the addon is shutting down."""
        if self.web_server_task:
            self.web_server_task.cancel()
        if self.client_session:
            await self.client_session.close()
        print("Galdr Addon Shutting Down.")

    async def send_event(self, event_type, data):
        """Sends an event to the GUI's event server."""
        if not self.client_session:
            return
        event = {"type": event_type, "data": data}
        try:
            await self.client_session.post(
                f"http://127.0.0.1:{self.event_port}/event",
                json=event,
                timeout=2
            )
        except Exception as e:
            # GUI might not be running or available, log silently
            # ctx.log.warn(f"Could not send event to GUI: {e}")
            pass

    async def handle_command(self, request):
        """Handles commands posted from the GUI."""
        try:
            command = await request.json()
            action = command.get("action")
            flow_id = command.get("flow_id")

            if action == "update_state":
                self.state.update(command.get("data", {}))
                # ctx.log.info(f"State updated: {self.state}")
                return web.Response(text="OK")

            if flow_id in self.pending_commands:
                # Set the result for the waiting future
                self.pending_commands[flow_id].set_result(command)
                return web.Response(text="OK")
            else:
                return web.Response(text="Flow not found or already handled", status=404)
        except Exception as e:
            ctx.log.error(f"Error handling command: {e}")
            return web.Response(text="Error", status=500)

    async def run_command_server(self):
        """Runs the HTTP server to listen for commands from the GUI."""
        app = web.Application()
        app.router.add_post('/command', self.handle_command)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', self.command_port)
        try:
            await site.start()
            # Keep the server running
            await asyncio.Future()
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()

    async def intercept_flow(self, flow: http.HTTPFlow, event_type: str, event_data: dict):
        """Generic flow interception logic."""
        flow.intercept()

        future = asyncio.get_event_loop().create_future()
        self.pending_commands[flow.id] = future

        await self.send_event(event_type, event_data)

        try:
            # Wait for the command from the GUI, with a timeout
            command = await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            ctx.log.warn(f"Timeout waiting for command for flow {flow.id}. Resuming.")
            flow.resume()
            return

        finally:
            # Clean up the pending command
            del self.pending_commands[flow.id]

        # Process the command
        action = command.get('action')
        if action == 'drop':
            flow.kill()
        elif action == 'forward':
            modified_data = command.get('data', {})
            self.apply_modifications(flow, modified_data)
            flow.resume()
        else: # Failsafe
            flow.resume()

    def apply_modifications(self, flow: http.HTTPFlow, data: dict):
        """Applies request/response modifications from a command."""
        if 'request' in data and flow.request:
            req_data = data['request']
            if 'body' in req_data:
                flow.request.text = req_data['body']
            if 'headers' in req_data:
                flow.request.headers.clear()
                for k, v in req_data['headers'].items():
                    flow.request.headers[k] = v

        elif 'response' in data and flow.response:
            resp_data = data['response']
            if 'body' in resp_data:
                flow.response.text = resp_data['body']
            if 'status_code' in resp_data:
                flow.response.status_code = resp_data['status_code']
            if 'headers' in resp_data:
                flow.response.headers.clear()
                for k, v in resp_data['headers'].items():
                    flow.response.headers[k] = v

    async def request(self, flow: http.HTTPFlow):
        """Called for every request."""
        if self.state.get('intercept_requests', False):
            request_data = {
                'flow_id': flow.id,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': flow.request.get_text(strict=False)
            }
            await self.intercept_flow(flow, "request_intercepted", request_data)

    async def response(self, flow: http.HTTPFlow):
        """Called for every response."""
        # Log every completed flow to the history
        if flow.response:
            log_data = {
                'id': flow.id,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'status': flow.response.status_code,
                'size': len(flow.response.content or b''),
                # For repeater
                'headers': dict(flow.request.headers),
                'body': flow.request.get_text(strict=False)
            }
            await self.send_event("flow_log", log_data)

        # Intercept the response if required
        if self.state.get('intercept_responses', False) and not flow.killed:
            response_data = {
                'flow_id': flow.id,
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': flow.response.get_text(strict=False)
            }
            await self.intercept_flow(flow, "response_intercepted", response_data)

addons = [GaldrGUIAddon()]
