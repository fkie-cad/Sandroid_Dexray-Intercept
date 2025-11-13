import os.path
import threading
import asyncio
from subprocess import Popen, PIPE



class MitmProxyThread(threading.Thread):
    def __init__(self, mitm_args, verbose):
        super().__init__()
        self.daemon = True
        self.mitm_args = mitm_args
        self.mitm_proc = None
        self.verbose = verbose

    def run(self):
        mitm_cmd = ["mitmweb"]
        mitm_cmd.extend(self.mitm_args)
        self.mitm_proc = Popen(mitm_cmd, stdout=PIPE, stderr=PIPE, shell=False)
        if self.verbose:
                for bline in self.mitm_proc.stdout:
                    print(f"[MITMPROXY] {bline.decode("utf-8")}")

    def stop(self):
        if self.verbose:
            print("[MITMPROXY] Terminating mitmproxy process")
        self.mitm_proc.terminate()

class MitmproxyManager:

    def __init__(self, port, addons, verbose):
        self.port = port
        self.addons = addons
        self.mitm_args = ["-p", str(self.port)]
        self.verbose = verbose
        self.mitm_thread = MitmProxyThread(self.mitm_args, self.verbose)


    def _start_proxy(self):
        print("[MITMPROXY] Starting mitmproxy proxy")
        self.mitm_thread.start()


    def start_mitm_proxy(self):
        self.load_addons()
        self._start_proxy()

    def stop_mitm_proxy(self):
        print("[MITMPROXY] Stopping mitmproxy")
        self.mitm_thread.stop()

    def load_addons(self):
        if self.addons:
            for addon in self.addons:
                if os.path.exists(addon):
                    self.mitm_args.extend(["-s", addon])
                    if self.verbose:
                        print(f"[MITMPROXY] Loaded addon {addon}")
                else:
                    print(f"[MITMPROXY] Addon {addon} not found")