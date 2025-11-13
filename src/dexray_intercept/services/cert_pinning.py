import os
import socket

class CertPinningManager:
    def __init__(self, acp_arg: str, verbose: bool):
        self.acp_arg = acp_arg
        self.verbose = verbose
        self.acp_ip = ""
        self.acp_port = -1
        self.cert_path = ""


    def build_script_details(self):
        ip, port, cert = self.acp_arg.split(':')

        if port == "":
            self.acp_port = 8080
        else:
            self.acp_port = int(port)

        if ip == "":
            device_name = socket.gethostname()
            local_device_ip = socket.gethostbyname(device_name)
            self.acp_ip = local_device_ip
        else:
            self.acp_ip = ip

        if cert == "":
            self.cert_path = f"/home/{os.getlogin()}/.mitmproxy/mitmproxy-ca-cert.pem"
        else:
            self.cert_path = cert

        with open(self.cert_path, "r") as cert_file: # get cert from default mitm location
            lines = cert_file.readlines()
            lines[-1] = lines[-1].rstrip("\n")
            cert_data = "".join(lines)
            cert = f"export const CERT_PEM = `{cert_data}`;\n"

        if self.verbose:
            debug_mode = "export const DEBUG_MODE = true;\n"
        else:
            debug_mode = "export const DEBUG_MODE = false;\n"

        ip = f"export const PROXY_HOST = \"{self.acp_ip}\";\n"
        port = f"export const PROXY_PORT = {self.acp_port};\n"

        config = ""
        with open("./agent/anticertpinning/config.js", "r") as config_file:
            config = config_file.read()

        with open("./agent/anticertpinning/config_custom.js", "w") as config_file:
            config_file.write(debug_mode + cert + ip + port + config)
