import sys
import os
import re
import json
import asyncio
import subprocess

class Tunnel():
    cloudflare = "cloudflare"
    ngrok = "ngrok"
    disabled = "disabled"

    def __init__(self):
        self.url = ""
        self.kwargs = {}
        if sys.platform == "win32":
            self.kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

    async def open_tunnel(self, tutype, port, basedir):
        if tutype == Tunnel.cloudflare:
            print("Opening Cloudflare Tunnel!")
            self.process = await asyncio.create_subprocess_exec(
                os.path.join(basedir, "resources", "cloudflared"), "tunnel", "--url", f"http://localhost:{port}", "--output", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                **self.kwargs
            )

            async for line in self.process.stdout:
                line = line.decode().strip()

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "message" in data and "trycloudflare.com" in data["message"] and "https" in data["message"]:
                    #print(line)
                    #print(data['message'])
                    message = str(data["message"])
                    pattern = r'(https?://\S+)'

                    url = re.search(pattern, message)
                    if not url:
                        self.url = ""
                        return None
                    url = url.group(1)
                    self.url = url.replace('https', 'wss')
                    #print(self.url)
                    break

            return self.url

        elif tutype == Tunnel.disabled:
            return "disabled"
        
        elif tutype == Tunnel.ngrok:
            return "Nrgrok is not supported!"
    
    async def close(self):
        if self.process:
            self.process.terminate()
            await self.process.wait()
            self.process = None

async def main():
    tunnel = Tunnel()
    await tunnel.open_tunnel(Tunnel.cloudflare, 8080, os.path.dirname(os.path.abspath(__file__)))
    print(tunnel.url)
    await tunnel.close()

if __name__ == "__main__":
    asyncio.run(main())