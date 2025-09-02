#!/root/antizapret/venv/bin/python
import os
import pathlib
import subprocess
import argparse
import re
import shutil
from datetime import datetime
import json
import sqlite3
import time
from xtlsapi import XrayClient, utils
import tempfile
from contextlib import contextmanager


# --- Configuration Class ---
class Config:
    """Handles loading and accessing configuration from the setup file."""

    def __init__(self, setup_file_path="/root/antizapret/setup"):
        self.config = {}
        self.load_config(setup_file_path)

        # Define paths with defaults, overridden by the setup file
        self.ROOT_DIR = self.get("ROOT_DIR", "/root/antizapret")
        self.EASYRSA_DIR = self.get("EASYRSA_DIR", "/etc/openvpn/easyrsa3")
        self.OPENVPN_DIR = self.get("OPENVPN_DIR", "/etc/openvpn")
        self.WIREGUARD_DIR = self.get("WIREGUARD_DIR", "/etc/wireguard")
        self.XRAY_DB_PATH = self.get("XRAY_DB_PATH", "/root/antizapret/xray.db")
        self.XRAY_API_HOST = self.get("XRAY_API_HOST", "127.0.0.1")
        self.XRAY_API_PORT = int(self.get("XRAY_API_PORT", 10085))
        self.IP = "172" if self.get("ALTERNATIVE_IP", "n").lower() == "y" else "10"
        self.CLIENT_BASE_DIR = os.path.join(self.ROOT_DIR, "client")
        self.BACKUP_BASE_DIR = os.path.join(self.ROOT_DIR, "backup")
        self.SERVER_CONFIG_PATH = os.path.join(self.ROOT_DIR, "setup")

    def load_config(self, setup_file_path):
        if not os.path.exists(setup_file_path):
            raise FileNotFoundError(f"Setup file not found: {setup_file_path}")
        with open(setup_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        self.config[key.strip()] = value.strip()

    def get(self, key, default=None):
        return self.config.get(key, default)


# Global config instance
config = None


# --- Helper Functions ---
def handle_error(lineno, command, message=""):
    print(f"Error at line {lineno}: {command}")
    print(f"Message: {message}")
    try:
        lsb_release = subprocess.run(
            ["lsb_release", "-ds"], capture_output=True, text=True, check=True
        ).stdout.strip()
        uname_r = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, check=True
        ).stdout.strip()
        current_time = datetime.now().isoformat(timespec="seconds")
        print(f"{lsb_release} {uname_r} {current_time}")
    except subprocess.CalledProcessError as e:
        print(f"Could not get system info: {e}")
    exit(1)


def run_command(command_args, check=True, capture_output=True, text=True, **kwargs):
    print(f"Running: {' '.join(command_args)}")
    try:
        return subprocess.run(
            command_args,
            capture_output=capture_output,
            text=text,
            check=check,
            **kwargs,
        )
    except subprocess.CalledProcessError as e:
        handle_error(
            "N/A",
            " ".join(command_args),
            f"Command failed with exit code {e.returncode}:\n{e.stderr or e.stdout}",
        )
    except FileNotFoundError:
        handle_error(
            "N/A", " ".join(command_args), f"Command not found: {command_args[0]}"
        )
    except Exception as e:
        handle_error(
            "N/A", " ".join(command_args), f"An unexpected error occurred: {e}"
        )


@contextmanager
def file_lock(lock_file_path):
    """A context manager for creating a file-based lock."""
    lock_file = f"{lock_file_path}.lock"
    if os.path.exists(lock_file):
        raise IOError(
            f"Lock file {lock_file} already exists. Another instance may be running."
        )
    try:
        with open(lock_file, "w") as f:
            f.write(str(os.getpid()))
        yield
    finally:
        if os.path.exists(lock_file):
            os.remove(lock_file)


def extract_cert_content(cert_path):
    """Extracts the content of a certificate file using string manipulation."""
    try:
        with open(cert_path, "r") as f:
            content = f.read()
        start_marker = "-----BEGIN CERTIFICATE-----"
        end_marker = "-----END CERTIFICATE-----"
        start_index = content.find(start_marker)
        end_index = content.find(end_marker)
        if start_index != -1 and end_index != -1:
            return content[start_index : end_index + len(end_marker)]
    except IOError as e:
        print(f"Could not read certificate file {cert_path}: {e}")
    return ""


def modify_wg_config(config_path, client_name, new_peer_block=None):
    """
    Safely adds or removes a client from a WireGuard config file.
    If new_peer_block is None, it removes the client. Otherwise, it adds/replaces it.
    Returns True if the client was found and action was taken.
    """
    if not os.path.exists(config_path):
        return False

    with open(config_path, "r") as f:
        lines = f.readlines()

    new_lines = []
    client_found = False
    in_client_block = False

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == f"# Client = {client_name}":
            client_found = True
            # Skip the client block, which is '# Client', '# PrivateKey', '[Peer]', and its contents
            i += 1
            while i < len(lines) and lines[i].strip() != "":
                i += 1
            # Skip the blank line after the peer block
            if i < len(lines) and lines[i].strip() == "":
                i += 1
            continue
        new_lines.append(line)
        i += 1

    # Remove trailing blank lines
    while new_lines and new_lines[-1].strip() == "":
        new_lines.pop()

    if new_peer_block:
        new_lines.append("\n")
        new_lines.append(new_peer_block)
        new_lines.append("\n")

    with open(config_path, "w") as f:
        f.writelines(new_lines)

    return client_found


def sync_wireguard_config(interface_name):
    """Syncs the wireguard config safely without using shell=True."""
    if (
        run_command(
            ["systemctl", "is-active", "--quiet", f"wg-quick@{interface_name}"],
            check=False,
        ).returncode
        != 0
    ):
        return  # Interface is not active, no need to sync

    print(f"Syncing active WireGuard interface: {interface_name}")
    try:
        strip_cmd = ["wg-quick", "strip", interface_name]
        stripped_config_result = run_command(strip_cmd)

        sync_cmd = ["wg", "syncconf", interface_name, "/dev/stdin"]
        run_command(sync_cmd, input=stripped_config_result.stdout)
    except Exception as e:
        print(f"An error occurred during wg syncconf for {interface_name}: {e}")


def ask_client_name(client_name_var=None):
    """Prompts the user for a client name."""
    client_name = client_name_var
    if not client_name or not re.match(r"^[a-zA-Z0-9_-]{1,32}$", client_name):
        print(
            "\nEnter client name: 1–32 alphanumeric characters (a-z, A-Z, 0-9) with underscore (_) or dash (-)"
        )
        while True:
            client_name = input("Client name: ").strip()
            if re.match(r"^[a-zA-Z0-9_-]{1,32}$", client_name):
                break
            else:
                print("Invalid client name. Please try again.")
    return client_name


def ask_client_cert_expire(client_cert_expire_var=None):
    """Prompts the user for client certificate expiration days."""
    client_cert_expire = client_cert_expire_var
    if not client_cert_expire or not (
        isinstance(client_cert_expire, int) and 1 <= client_cert_expire <= 3650
    ):
        print("\nEnter client certificate expiration days (1-3650):")
        while True:
            client_cert_expire_input = input("Certificate expiration days: ").strip()
            if (
                client_cert_expire_input.isdigit()
                and 1 <= int(client_cert_expire_input) <= 3650
            ):
                return int(client_cert_expire_input)
            else:
                print(
                    "Invalid expiration days. Please enter a number between 1 and 3650."
                )
    return client_cert_expire


def set_server_host_file_name(client_name, server_host_override=""):
    """Sets SERVER_HOST and FILE_NAME based on client name and server host override."""
    global SERVER_HOST, FILE_NAME
    SERVER_HOST = server_host_override or SERVER_IP
    FILE_NAME = client_name.replace("antizapret-", "").replace("vpn-", "")
    FILE_NAME = f"{FILE_NAME}-({SERVER_HOST})"
    return SERVER_HOST, FILE_NAME


def set_server_ip():
    """Determines the server's IP address."""
    global SERVER_IP
    result = run_command(["ip", "-4", "addr"])
    for line in result.stdout.splitlines():
        match = re.search(
            r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+ scope global", line
        )
        if match:
            SERVER_IP = match.group(1)
            return SERVER_IP
    handle_error("N/A", "ip -4 addr", "Default IP address not found!")


def set_server_ip():
    """Читает SERVER_HOST из файла setup и возвращает его значение."""
    path = pathlib.Path("/root/antizapret/setup")
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("SERVER_HOST="):
                SERVER_IP = line.split("=", 1)[1].strip().strip("\"'")
                return SERVER_IP
    raise RuntimeError("SERVER_HOST не найден в setup")


def render(template_file_path, variables):
    """Renders a template file by replacing placeholders."""
    with open(template_file_path, "r") as f:
        content = f.read()
    for var_name, value in variables.items():
        content = content.replace(f"${{{var_name}}}", str(value))
    # Remove any unreplaced variables
    content = re.sub(r"\$\{[a-zA-Z_][a-zA-Z_0-9]*}", "", content)
    return content


# --- OpenVPN Functions ---
def init_openvpn():
    """Initializes OpenVPN EasyRSA PKI."""
    print("\nInitializing OpenVPN EasyRSA PKI...")
    pki_dir = os.path.join(config.EASYRSA_DIR, "pki")
    server_keys_dir = os.path.join(config.OPENVPN_DIR, "server/keys")
    client_keys_dir = os.path.join(config.OPENVPN_DIR, "client/keys")

    os.makedirs(config.EASYRSA_DIR, exist_ok=True)
    os.chdir(config.EASYRSA_DIR)

    if not all(
        os.path.exists(p)
        for p in [
            os.path.join(pki_dir, "ca.crt"),
            os.path.join(pki_dir, "issued/antizapret-server.crt"),
        ]
    ):
        print("PKI not found or incomplete. Initializing new PKI...")
        shutil.rmtree(pki_dir, ignore_errors=True)
        shutil.rmtree(server_keys_dir, ignore_errors=True)
        shutil.rmtree(client_keys_dir, ignore_errors=True)

        run_command(["/usr/share/easy-rsa/easyrsa", "init-pki"])
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "--req-cn=AntiZapret CA",
                "build-ca",
                "nopass",
            ],
            env={"EASYRSA_CA_EXPIRE": "3650", **os.environ},
        )
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "build-server-full",
                "antizapret-server",
                "nopass",
            ],
            env={"EASYRSA_CERT_EXPIRE": "3650", **os.environ},
        )
    else:
        print("OpenVPN PKI already initialized.")

    os.makedirs(server_keys_dir, exist_ok=True)
    os.makedirs(client_keys_dir, exist_ok=True)

    # Copy server keys
    for f in ["ca.crt", "antizapret-server.crt", "antizapret-server.key"]:
        src_path = os.path.join(
            pki_dir,
            (
                "issued"
                if ".crt" in f and f != "ca.crt"
                else ("private" if ".key" in f else "")
            ),
            f,
        )
        dest_path = os.path.join(server_keys_dir, f)
        if not os.path.exists(dest_path):
            shutil.copy(src_path, dest_path)

    # Generate CRL
    crl_path = os.path.join(server_keys_dir, "crl.pem")
    if not os.path.exists(crl_path):
        print("Generating CRL...")
        run_command(
            ["/usr/share/easy-rsa/easyrsa", "gen-crl"],
            env={"EASYRSA_CRL_DAYS": "3650", **os.environ},
        )
        shutil.copy(os.path.join(pki_dir, "crl.pem"), crl_path)
        os.chmod(crl_path, 0o644)

    os.chdir(config.ROOT_DIR)


def add_openvpn(client_name, client_cert_expire_days):
    """Adds an OpenVPN client or renews its certificate."""
    print(f"\nAdding/Renewing OpenVPN client: {client_name}")

    client_dir = os.path.join(config.CLIENT_BASE_DIR, client_name)
    if os.path.isdir(client_dir):
        print(f"Cleaning up old OpenVPN profiles for {client_name}...")
        for f in os.listdir(client_dir):
            if f.endswith(".ovpn"):
                os.remove(os.path.join(client_dir, f))

    set_server_host_file_name(client_name, config.get("OPENVPN_HOST"))
    os.chdir(config.EASYRSA_DIR)

    client_crt_path = f"./pki/issued/{client_name}.crt"
    client_key_path = f"./pki/private/{client_name}.key"

    if os.path.exists(client_crt_path) or os.path.exists(client_key_path):
        print(f"Client '{client_name}' already exists. Forcing renewal...")
        for p in [client_crt_path, client_key_path, f"./pki/reqs/{client_name}.req"]:
            if os.path.exists(p):
                os.remove(p)
    else:
        print("Client does not exist. Building new client certificate.")

    client_cert_expire_days = ask_client_cert_expire(client_cert_expire_days)
    run_command(
        [
            "/usr/share/easy-rsa/easyrsa",
            "--batch",
            "build-client-full",
            client_name,
            "nopass",
        ],
        env={"EASYRSA_CERT_EXPIRE": str(client_cert_expire_days), **os.environ},
    )

    # Copy client keys
    client_keys_dir = os.path.join(config.OPENVPN_DIR, "client/keys")
    shutil.copy(client_crt_path, os.path.join(client_keys_dir, f"{client_name}.crt"))
    shutil.copy(client_key_path, os.path.join(client_keys_dir, f"{client_name}.key"))

    # Get cert contents
    ca_cert_content = extract_cert_content(
        os.path.join(config.OPENVPN_DIR, "server/keys/ca.crt")
    )
    client_cert_content = extract_cert_content(
        os.path.join(client_keys_dir, f"{client_name}.crt")
    )
    with open(os.path.join(client_keys_dir, f"{client_name}.key"), "r") as f:
        client_key_content = f.read()

    if not all([ca_cert_content, client_cert_content, client_key_content]):
        handle_error("N/A", "Key loading", "Cannot load client keys!")

    os.makedirs(client_dir, exist_ok=True)
    current_date = datetime.now().strftime("%y-%m-%d")

    render_vars = {
        "SERVER_HOST": SERVER_HOST,
        "CA_CERT": ca_cert_content,
        "CLIENT_CERT": client_cert_content,
        "CLIENT_KEY": client_key_content,
        "SERVER_IP": SERVER_IP,
        **config.config,
    }

    templates_dir = os.path.join(config.OPENVPN_DIR, "client/templates")
    templates = {
        "antizapret-udp.conf": f"AZ-UDP-{current_date}.ovpn",
        "antizapret-tcp.conf": f"AZ-TCP-{current_date}.ovpn",
        "antizapret.conf": f"AZ-U+T-{current_date}.ovpn",
        "vpn-udp.conf": f"GL-UDP-{current_date}.ovpn",
        "vpn-tcp.conf": f"GL-TCP-{current_date}.ovpn",
        "vpn.conf": f"GL-U+T-{current_date}.ovpn",
    }

    for template, output_filename in templates.items():
        template_path = os.path.join(templates_dir, template)
        if os.path.exists(template_path):
            output_path = os.path.join(client_dir, output_filename)
            rendered_content = render(template_path, render_vars)
            with open(output_path, "w") as f:
                f.write(rendered_content)

    print(
        f"OpenVPN profile files (re)created for client '{client_name}' at {client_dir}"
    )
    os.chdir(config.ROOT_DIR)


def delete_openvpn(client_name):
    """Deletes an OpenVPN client."""
    print(f"\nDeleting OpenVPN client: {client_name}")
    os.chdir(config.EASYRSA_DIR)

    run_command(["/usr/share/easy-rsa/easyrsa", "--batch", "revoke", client_name])
    run_command(
        [
            "/usr/share/easy-rsa/easyrsa",
            "gen-crl",
        ],
        env={"EASYRSA_CRL_DAYS": "3650", **os.environ},
    )
    crl_src = os.path.join(config.EASYRSA_DIR, "pki/crl.pem")
    crl_dest = os.path.join(config.OPENVPN_DIR, "server/keys/crl.pem")
    shutil.copy(crl_src, crl_dest)
    os.chmod(crl_dest, 0o644)

    for ext in [".crt", ".key"]:
        p = os.path.join(config.OPENVPN_DIR, f"client/keys/{client_name}{ext}")
        if os.path.exists(p):
            os.remove(p)
    # Remove OpenVPN specific files from the client directory
    client_dir = os.path.join(config.CLIENT_BASE_DIR, client_name)
    if os.path.isdir(client_dir):
        for f in os.listdir(client_dir):
            if f.endswith(".ovpn"):
                os.remove(os.path.join(client_dir, f))

    print(f"OpenVPN client '{client_name}' successfully deleted")
    os.chdir(config.ROOT_DIR)


def list_openvpn():
    """Lists OpenVPN client names."""
    print("\nOpenVPN client names:")
    issued_dir = os.path.join(config.EASYRSA_DIR, "pki/issued")
    if not os.path.isdir(issued_dir):
        print("No OpenVPN clients found.")
        return []

    clients = [
        f.replace(".crt", "")
        for f in os.listdir(issued_dir)
        if f.endswith(".crt") and f != "antizapret-server.crt"
    ]
    for client in sorted(clients):
        print(client)
    return sorted(clients)


# --- WireGuard Functions ---
def init_wireguard():
    """Initializes WireGuard server keys and configuration."""
    print("\nInitializing WireGuard/AmneziaWG server keys...")
    os.makedirs(config.WIREGUARD_DIR, exist_ok=True)
    key_path = os.path.join(config.WIREGUARD_DIR, "key")

    if not os.path.exists(key_path):
        private_key = run_command(["wg", "genkey"]).stdout.strip()
        public_key = run_command(["wg", "pubkey"], input=private_key).stdout.strip()

        with open(key_path, "w") as f:
            f.write(f"PRIVATE_KEY={private_key}\nPUBLIC_KEY={public_key}\n")

        render_vars = {
            "PRIVATE_KEY": private_key,
            "PUBLIC_KEY": public_key,
            "SERVER_IP": SERVER_IP,
            **config.config,
        }

        templates_dir = os.path.join(config.WIREGUARD_DIR, "templates")
        for conf_name in ["antizapret.conf", "vpn.conf"]:
            template_path = os.path.join(templates_dir, conf_name)
            if os.path.exists(template_path):
                rendered_conf = render(template_path, render_vars)
                with open(os.path.join(config.WIREGUARD_DIR, conf_name), "w") as f:
                    f.write(rendered_conf)
        print("WireGuard/AmneziaWG server keys and configs generated.")
    else:
        print("WireGuard/AmneziaWG server keys already exist.")


def add_wireguard(client_name):
    """Adds or recreates a WireGuard client."""
    print(f"\nAdding WireGuard/AmneziaWG client: {client_name}")

    client_dir = os.path.join(config.CLIENT_BASE_DIR, client_name)
    if os.path.isdir(client_dir):
        print(f"Cleaning up old WireGuard/AmneziaWG profiles for {client_name}...")
        for f in os.listdir(client_dir):
            if f.endswith(".conf"):
                os.remove(os.path.join(client_dir, f))

    set_server_host_file_name(client_name, config.get("WIREGUARD_HOST"))

    key_path = os.path.join(config.WIREGUARD_DIR, "key")
    if not os.path.exists(key_path):
        handle_error(
            "N/A",
            "WireGuard key loading",
            "WireGuard server keys not found. Run init_wireguard first.",
        )

    with open(key_path, "r") as f:
        content = f.read()
        server_public_key = re.search(r"PUBLIC_KEY=(.*)", content).group(1)

    ips_path = os.path.join(config.WIREGUARD_DIR, "ips")
    ips_content = open(ips_path, "r").read() if os.path.exists(ips_path) else ""

    os.makedirs(client_dir, exist_ok=True)
    current_date = datetime.now().strftime("%y-%m-%d")

    for wg_type in ["antizapret", "vpn"]:
        print(f"Processing {wg_type.capitalize()} WireGuard configuration...")
        conf_path = os.path.join(config.WIREGUARD_DIR, f"{wg_type}.conf")
        lock_path = f"{conf_path}.lock"

        with file_lock(lock_path):
            if modify_wg_config(conf_path, client_name):
                print(f"Client '{client_name}' exists in {wg_type}.conf. Recreating...")

            client_private_key = run_command(["wg", "genkey"]).stdout.strip()
            client_public_key = run_command(
                ["wg", "pubkey"], input=client_private_key
            ).stdout.strip()
            client_preshared_key = run_command(["wg", "genpsk"]).stdout.strip()

            with open(conf_path, "r") as f:
                conf_content = f.read()
                base_ip_match = re.search(
                    r"Address = (\d{1,3}\.\d{1,3}\.\d{1,3})", conf_content
                )
                base_client_ip = base_ip_match.group(1)

                existing_ips = set(
                    re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", conf_content)
                )

            client_ip = ""
            for i in range(2, 255):
                potential_ip = f"{base_client_ip}.{i}"
                if potential_ip not in existing_ips:
                    client_ip = potential_ip
                    break

            if not client_ip:
                handle_error(
                    "N/A", "IP assignment", f"No available IPs in the {wg_type} subnet!"
                )

            new_peer_block = (
                f"# Client = {client_name}\n# PrivateKey = {client_private_key}\n[Peer]\n"
                f"PublicKey = {client_public_key}\nPresharedKey = {client_preshared_key}\n"
                f"AllowedIPs = {client_ip}/32"
            )
            modify_wg_config(conf_path, client_name, new_peer_block)

        sync_wireguard_config(wg_type)

        render_vars = {
            "SERVER_HOST": SERVER_HOST,
            "SERVER_PUBLIC_KEY": server_public_key,
            "CLIENT_PRIVATE_KEY": client_private_key,
            "CLIENT_PUBLIC_KEY": client_public_key,
            "CLIENT_PRESHARED_KEY": client_preshared_key,
            "CLIENT_IP": client_ip,
            "IPS": ips_content,
            **config.config,
        }

        templates_dir = os.path.join(config.WIREGUARD_DIR, "templates")
        prefix = "AZ" if wg_type == "antizapret" else "GL"

        for suffix in ["wg", "am"]:
            template_name = f"{wg_type}-client-{suffix}.conf"
            output_name = f"{prefix}-{suffix.upper()}-{current_date}.conf"
            template_path = os.path.join(templates_dir, template_name)
            if os.path.exists(template_path):
                rendered_conf = render(template_path, render_vars)
                with open(os.path.join(client_dir, output_name), "w") as f:
                    f.write(rendered_conf)

    print(
        f"WireGuard/AmneziaWG profile files (re)created for client '{client_name}' at {client_dir}"
    )
    print(
        "\nAttention! If import fails, shorten profile filename to 32 chars (Windows) or 15 (Linux/Android/iOS), remove parentheses"
    )


def delete_wireguard(client_name):
    """Deletes a WireGuard client."""
    print(f"\nDeleting WireGuard/AmneziaWG client: {client_name}")

    client_found = False
    for wg_type in ["antizapret", "vpn"]:
        conf_path = os.path.join(config.WIREGUARD_DIR, f"{wg_type}.conf")
        if modify_wg_config(conf_path, client_name, new_peer_block=None):
            print(f"Removed client '{client_name}' from {wg_type}.conf")
            client_found = True
            sync_wireguard_config(wg_type)

    if not client_found:
        print(
            f"Failed to delete client '{client_name}'! Client not found in any config."
        )
        return

    # Remove WireGuard specific files from the client directory
    client_dir = os.path.join(config.CLIENT_BASE_DIR, client_name)
    if os.path.isdir(client_dir):
        for f in os.listdir(client_dir):
            if f.endswith(".conf") and ("AZ-" in f or "GL-" in f):
                os.remove(os.path.join(client_dir, f))
    print(f"WireGuard/AmneziaWG client '{client_name}' successfully deleted")


def delete_all_protocols(client_name, xray_client):
    """Deletes a client across all supported protocols."""
    print(f"\nDeleting client '{client_name}' from all protocols...")
    delete_openvpn(client_name)
    delete_wireguard(client_name)
    handle_remove_user(argparse.Namespace(name=client_name), xray_client)
    print(f"Client '{client_name}' deletion across all protocols completed.")
    # Clean up client directory if empty
    client_dir = os.path.join(config.CLIENT_BASE_DIR, client_name)
    if os.path.isdir(client_dir) and not os.listdir(client_dir):
        print(f"Removing empty client directory: {client_dir}")
        shutil.rmtree(client_dir)


def list_wireguard():
    """Lists WireGuard client names."""
    print("\nWireGuard/AmneziaWG client names:")
    clients = set()
    for wg_type in ["antizapret", "vpn"]:
        conf_path = os.path.join(config.WIREGUARD_DIR, f"{wg_type}.conf")
        if os.path.exists(conf_path):
            with open(conf_path, "r") as f:
                clients.update(re.findall(r"^# Client = (.*)", f.read(), re.M))

    sorted_clients = sorted([c.strip() for c in clients])
    for client in sorted_clients:
        print(client)
    return sorted_clients


# --- General Functions ---
def recreate_profiles(xray_client):
    """Recreates all client profile files safely."""
    print("\nRecreating client profile files...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Temporarily set the client base dir to the temp dir
        original_client_dir = config.CLIENT_BASE_DIR
        config.CLIENT_BASE_DIR = temp_dir

        try:
            # Re-add OpenVPN clients
            print("\nRe-adding OpenVPN profiles...")
            openvpn_clients = list_openvpn()
            if openvpn_clients:
                init_openvpn()
                for client_name in openvpn_clients:
                    add_openvpn(client_name, 3650)
            else:
                print("No OpenVPN clients found.")

            # Re-add WireGuard clients
            print("\nRe-adding WireGuard/AmneziaWG profiles...")
            wireguard_clients = list_wireguard()
            if wireguard_clients:
                init_wireguard()
                for client_name in wireguard_clients:
                    add_wireguard(client_name)
            else:
                print("No WireGuard/AmneziaWG clients found.")

            # Re-add VLESS users
            print("\nRe-adding VLESS profiles...")
            vless_users = get_all_users_from_db()
            if vless_users:
                for user in vless_users:
                    handle_add_user(
                        argparse.Namespace(name=user["email"]),
                        xray_client,
                    )
            else:
                print("No VLESS users found.")

            # Replace old client directory with the new one
            if os.path.exists(original_client_dir):
                shutil.rmtree(original_client_dir)
            shutil.copytree(temp_dir, original_client_dir, dirs_exist_ok=True)
            print("\nSuccessfully recreated all client profiles.")

        finally:
            # Restore original config path
            config.CLIENT_BASE_DIR = original_client_dir


def backup_config():
    """Backs up configuration and client data."""
    print("\nBacking up configuration and clients...")

    with tempfile.TemporaryDirectory() as backup_dir:
        backup_items = {
            "easyrsa3": config.EASYRSA_DIR,
            "wireguard": config.WIREGUARD_DIR,
            "xray_db": config.XRAY_DB_PATH,
            "config": os.path.join(config.ROOT_DIR, "config"),
        }

        tar_sources = []
        for name, path in backup_items.items():
            if os.path.exists(path):
                dest_path = os.path.join(
                    backup_dir,
                    name if not name.endswith("_db") else os.path.basename(path),
                )
                if os.path.isdir(path):
                    shutil.copytree(path, dest_path)
                else:  # is file
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    shutil.copy(path, dest_path)
                tar_sources.append(os.path.basename(dest_path))
            else:
                print(f"Warning: Path not found, skipping backup for '{name}': {path}")

        if not tar_sources:
            print("Nothing to back up.")
            return

        backup_file = os.path.join(config.ROOT_DIR, f"backup-{SERVER_IP}.tar.gz")
        run_command(["tar", "-czf", backup_file, "-C", backup_dir] + tar_sources)
        print(f"Backup of configuration and client data created at {backup_file}")


# --- Xray Constants ---
INBOUND_TAG = "in-vless"


# --- Xray Database Functions ---
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(config.XRAY_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def create_table():
    """Creates the users table if it doesn't exist."""
    if not os.path.exists(os.path.dirname(config.XRAY_DB_PATH)):
        os.makedirs(os.path.dirname(config.XRAY_DB_PATH))
    with get_db_connection() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (uuid TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_email ON users (email)")


def add_user_to_db(uuid, email):
    """Adds a user to the SQLite database."""
    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO users (uuid, email) VALUES (?, ?)", (uuid, email))
            return True
    except sqlite3.IntegrityError:
        print(f"Error: User with email '{email}' already exists.")
        return False


def get_user_by_email_from_db(email):
    """Retrieves a single user from the database by email."""
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def remove_user_from_db(uuid):
    """Removes a user from the SQLite database."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE uuid = ?", (uuid,))


def get_all_users_from_db():
    """Retrieves all users from the SQLite database."""
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM users").fetchall()


# --- Xray & System Functions ---
def get_xray_client(host, port):
    """Returns an XrayClient instance, raising an exception on failure."""
    try:
        return XrayClient(host, port)
    except Exception as e:
        raise ConnectionError(f"Error connecting to Xray API on {host}:{port}: {e}")


def generate_client_config(
    user_id, server_host, public_key, server_names, vless_port, short_id
):
    """Generates the client-side VLESS configuration dictionary."""
    route_ips_list = []
    route_ips_file = "/root/antizapret/result/route-ips.txt"
    if os.path.exists(route_ips_file):
        with open(route_ips_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    route_ips_list.append(line)

    # This function remains largely the same, just ensure variables are passed correctly.
    return {
        "dns": {"servers": [f"{config.IP}.29.12.1"]},
        "fakedns": [
            {"ipPool": "198.20.0.0/15", "poolSize": 128},
            {"ipPool": "fc00::/64", "poolSize": 128},
        ],
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "destOverride": ["http", "tls", "quic"],
                    "enabled": True,
                    "routeOnly": True,
                },
                "tag": "in-vless",
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": server_host,
                            "port": int(vless_port),
                            "users": [
                                {
                                    "id": user_id,
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "realitySettings": {
                        "fingerprint": "chrome",
                        "publicKey": public_key,
                        "serverName": server_names,
                        "shortId": short_id,
                    },
                    "security": "reality",
                    "tcpSettings": {
                        "header": {"type": "none", "request": {"headers": {}}}
                    },
                },
                "tag": "proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPOnDemand",
            "rules": [
                {
                    "ip": ["10.30.0.0/15", f"{config.IP}.29.12.1"] + route_ips_list,
                    "outboundTag": "proxy",
                    "type": "field",
                },
                {
                    "domain": ["geosite:private"],
                    "outboundTag": "direct",
                    "type": "field",
                },
                {"ip": ["0.0.0.0/0"], "outboundTag": "direct", "type": "field"},
            ],
        },
    }


# --- Xray Command Handlers ---
def wait_for_xray_api(xray_client, max_retries=10, delay=3):
    print("Waiting for Xray API to be available...")
    for i in range(max_retries):
        try:
            xray_client.get_inbound_download_traffic(INBOUND_TAG)
            print("Xray API is available.")
            return True
        except Exception:
            print(
                f"Attempt {i+1}/{max_retries}: Xray API not ready. Retrying in {delay} seconds..."
            )
            time.sleep(delay)
    print("Failed to connect to Xray API after multiple retries.")
    return False


def generate_vless_link(
    user_id, server_host, public_key, server_names, vless_port, short_id, identifier
):
    """Generates a VLESS configuration link."""
    params = {
        "type": "tcp",
        "security": "reality",
        "flow": "xtls-rprx-vision",
        "fp": "chrome",
        "pbk": public_key,
        "sni": server_names,
        "sid": short_id,
    }
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return f"vless://{user_id}@{server_host}:{vless_port}?{query_string}#{identifier}"


def handle_add_user(args, xray_client):
    email = args.name or input("Enter user email: ")
    user = get_user_by_email_from_db(email)

    if user:
        print(f"User '{email}' exists. Recreating client config...")
        client_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", email)
        client_dir = os.path.join(config.CLIENT_BASE_DIR, client_name)
        if os.path.isdir(client_dir):
            print(f"Cleaning up old VLESS profiles for {email}...")
            for f in os.listdir(client_dir):
                if f.endswith(".json") or f.endswith(".txt"):
                    os.remove(os.path.join(client_dir, f))
        user_id = user["uuid"]
        xray_client.remove_client(INBOUND_TAG, email)
    else:
        print(f"Creating new user '{email}'.")
        user_id = utils.generate_random_user_id()
        if not add_user_to_db(user_id, email):
            return
        try:
            if not xray_client.add_client(
                INBOUND_TAG, user_id, email, flow="xtls-rprx-vision"
            ):
                print(
                    f"Failed to add user '{email}' to Xray. The user may already exist."
                )
                remove_user_from_db(user_id)
                return
            print(f"User '{email}' successfully added to Xray.")
        except Exception as e:
            print(f"An exception occurred while adding user to Xray: {e}")
            remove_user_from_db(user_id)
            return

    server_host = config.get("SERVER_HOST")
    public_key = config.get("VLESS_PUBLIC_KEY")
    server_names = config.get("VLESS_SERVER_NAMES")
    short_id = config.get("VLESS_SHORT_ID")

    if not all([server_host, public_key, server_names, short_id]):
        print(f"Error: Missing VLESS config in {config.SERVER_CONFIG_PATH}")
        return

    # Generate AZ-XR JSON config
    client_config = generate_client_config(
        user_id, server_host, public_key, server_names, 443, short_id
    )
    client_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", email)
    dir_path = os.path.join(config.CLIENT_BASE_DIR, client_name)
    os.makedirs(dir_path, exist_ok=True)
    file_path_json = os.path.join(
        dir_path, f"AZ-XR-{datetime.now().strftime('%y-%m-%d')}.json"
    )
    with open(file_path_json, "w") as f:
        json.dump(client_config, f, indent=4)
    print(f"Client config saved to: {file_path_json}")

    # Generate GL-XR VLESS link
    vless_link = generate_vless_link(
        user_id, server_host, public_key, server_names, 443, short_id, email + "-GL"
    )
    file_path_txt = os.path.join(
        dir_path, f"GL-XR-{datetime.now().strftime('%y-%m-%d')}.txt"
    )
    with open(file_path_txt, "w") as f:
        f.write(vless_link)
    print(f"VLESS link saved to: {file_path_txt}")


def handle_remove_user(args, xray_client):
    email = args.name or input("Enter user email: ")
    user = get_user_by_email_from_db(email)
    if not user:
        print(f"Error: User with email '{email}' not found.")
        return
    try:
        xray_client.remove_client(INBOUND_TAG, email)
        print(f"User '{email}' removed from Xray.")
    except Exception as e:
        print(
            f"Warning: Could not remove user from Xray (user might not exist there): {e}"
        )

    remove_user_from_db(user["uuid"])
    print(f"User '{email}' removed from database.")
    # Remove VLESS/Xray specific files from the client directory
    client_dir = os.path.join(
        config.CLIENT_BASE_DIR, re.sub(r"[^a-zA-Z0-9_.-]", "_", email)
    )
    if os.path.isdir(client_dir):
        for f in os.listdir(client_dir):
            if f.endswith(".json") or f.endswith(".txt"):
                os.remove(os.path.join(client_dir, f))


def handle_list_users(args, xray_client):
    users = get_all_users_from_db()
    if not users:
        print("No users found in the database.")
        return
    print("\n--- User List ---")
    for i, user in enumerate(users, 1):
        print(f"{i}. Email: {user['email']} | UUID: {user['uuid']}")
    print("-----------------")


def handle_load_all_users(args, xray_client):
    print("Loading all users from database into Xray...")
    users = get_all_users_from_db()
    if not users:
        print("No users found to load.")
        return

    loaded, skipped = 0, 0
    for user in users:
        try:
            if xray_client.add_client(
                INBOUND_TAG, user["uuid"], user["email"], flow="xtls-rprx-vision"
            ):
                print(f"  Loaded user: {user['email']}")
                loaded += 1
            else:
                print(f"  Skipping user {user['email']}: already exists on server.")
                skipped += 1
        except Exception as e:
            print(f"  Error loading user {user['email']}: {e}")
            skipped += 1
    print(f"Finished. Loaded: {loaded}, Skipped/Errors: {skipped}.")


# Global variables
SERVER_IP = None
SERVER_HOST = None
FILE_NAME = None


def main():
    global config, SERVER_IP

    try:
        config = Config()
    except FileNotFoundError as e:
        handle_error("N/A", "Config initialization", str(e))

    os.environ["LC_ALL"] = "C"
    set_server_ip()

    parser = argparse.ArgumentParser(
        description="Manage VPN clients (OpenVPN, WireGuard/AmneziaWG, VLESS)."
    )
    parser.add_argument("n", nargs="?", type=int, help="Option choice")
    parser.add_argument("name", nargs="?", help="Client name or email")
    parser.add_argument(
        "date", nargs="?", type=int, help="Certificate expiration days (for OpenVPN)"
    )
    args = parser.parse_args()

    option = args.n
    client_name = args.name
    client_cert_expire = args.date

    def get_xray_client_interactive():
        try:
            client = get_xray_client(config.XRAY_API_HOST, config.XRAY_API_PORT)
            if not wait_for_xray_api(client):
                return None
            return client
        except ConnectionError as e:
            print(e)
            return None

    if not option:
        # Interactive menu
        while True:
            print("\nPlease choose option:")
            # Menu options...
            print("    1) OpenVPN - Add/Renew client")
            print("    2) OpenVPN - Delete client")
            print("    3) OpenVPN - List clients")
            print("    4) WireGuard/AmneziaWG - Add client")
            print("    5) WireGuard/AmneziaWG - Delete client")
            print("    6) WireGuard/AmneziaWG - List clients")
            print("    7) VLESS - Add user")
            print("    8) VLESS - Remove user")
            print("    9) VLESS - List users")
            print("    10) VLESS - Load all users from DB to Xray")
            print("    11) Create all VPN client types")
            print("    12) Delete client from all protocols")
            print("    13) Recreate client profile files")
            print("    14) Backup configuration and clients")
            print("    15) Exit")

            try:
                option_input = input("Option choice [1-15]: ").strip()
                if not option_input:
                    continue
                option = int(option_input)
            except (ValueError, KeyboardInterrupt):
                print("\nExiting...")
                break

            if option == 1:
                client_name = ask_client_name()
                init_openvpn()
                add_openvpn(client_name, ask_client_cert_expire())
            elif option == 2:
                list_openvpn()
                delete_openvpn(ask_client_name())
            elif option == 3:
                list_openvpn()
            elif option == 4:
                client_name = ask_client_name()
                init_wireguard()
                add_wireguard(client_name)
            elif option == 5:
                list_wireguard()
                delete_wireguard(ask_client_name())
            elif option == 6:
                list_wireguard()
            elif 7 <= option <= 13:
                create_table()
                xray_client = get_xray_client_interactive()
                if not xray_client:
                    continue

                if option == 7:
                    handle_add_user(argparse.Namespace(name=None), xray_client)
                elif option == 8:
                    handle_remove_user(argparse.Namespace(name=None), xray_client)
                elif option == 9:
                    handle_list_users(None, xray_client)
                elif option == 10:
                    handle_load_all_users(None, xray_client)
                elif option == 11:
                    client_name = ask_client_name()
                    init_openvpn()
                    add_openvpn(client_name, ask_client_cert_expire())
                    init_wireguard()
                    add_wireguard(client_name)
                    handle_add_user(argparse.Namespace(name=client_name), xray_client)
                elif option == 12:
                    delete_all_protocols(ask_client_name(), xray_client)
                elif option == 13:
                    recreate_profiles(xray_client)
            elif option == 14:
                backup_config()
            elif option == 15:
                print("Exiting...")
                break
            else:
                print("Invalid option selected.")
    else:
        # Non-interactive mode
        xray_client = None
        if 7 <= option <= 13:
            create_table()
            try:
                xray_client = get_xray_client(
                    config.XRAY_API_HOST, config.XRAY_API_PORT
                )
                if not wait_for_xray_api(xray_client):
                    return
            except ConnectionError as e:
                print(e)
                return

        if option == 1:
            init_openvpn()
            add_openvpn(client_name, client_cert_expire)
        elif option == 2:
            delete_openvpn(client_name)
        elif option == 3:
            list_openvpn()
        elif option == 4:
            init_wireguard()
            add_wireguard(client_name)
        elif option == 5:
            delete_wireguard(client_name)
        elif option == 6:
            list_wireguard()
        elif option == 7:
            handle_add_user(args, xray_client)
        elif option == 8:
            handle_remove_user(args, xray_client)
        elif option == 9:
            handle_list_users(args, xray_client)
        elif option == 10:
            handle_load_all_users(args, xray_client)
        elif option == 11:
            init_openvpn()
            add_openvpn(client_name, client_cert_expire)
            init_wireguard()
            add_wireguard(client_name)
            handle_add_user(args, xray_client)
        elif option == 12:
            delete_all_protocols(client_name, xray_client)
        elif option == 13:
            recreate_profiles(xray_client)
        elif option == 14:
            backup_config()
        else:
            print("Invalid option selected.")


if __name__ == "__main__":
    os.umask(0o022)
    main()
