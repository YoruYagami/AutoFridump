#!/usr/bin/env python3
import frida
import os
import sys
import argparse
import logging
import textwrap
import time
import json
import re
import subprocess

# ---------------------
# Session Management
# ---------------------

SESSION_FILE = "fridump_session.json"

def load_session_data(filepath):
    if not os.path.isfile(filepath):
        return {"dumped_ranges": {}, "skipped_ranges": {}}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"dumped_ranges": {}, "skipped_ranges": {}}
        if "dumped_ranges" not in data or "skipped_ranges" not in data:
            return {"dumped_ranges": {}, "skipped_ranges": {}}
        return data
    except Exception:
        return {"dumped_ranges": {}, "skipped_ranges": {}}

def save_session_data(filepath, dumped, skipped):
    data = {
        "dumped_ranges": dumped,
        "skipped_ranges": skipped
    }
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logging.error(f"Cannot save session data to {filepath}: {e}")

# ---------------------
# Logo
# ---------------------

logo = r"""
        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __    
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \
        | | | |  | | (_| | |_| | | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|
"""

# ---------------------
# Argument Parsing
# ---------------------

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help(sys.stderr)
        sys.exit(2)

def MENU():
    parser = CustomArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            A memory dumping tool with session tracking.
            By default, it dumps memory regions with 'rw-' permissions, but you can specify
            multiple permissions with the -p/--perms argument, e.g. '--perms r--,rw-,r-x'
        """)
    )
    parser.add_argument(
        'process',
        nargs='?',
        help='Process name or PID to attach to (e.g. com.example.app or 1234).'
    )
    parser.add_argument(
        '-o', '--out',
        type=str,
        help="Specify an output directory for dumps (default: ./dump).",
        metavar="DIR"
    )
    parser.add_argument(
        '-u', '--usb',
        action='store_true',
        help='Use a device connected over USB.'
    )
    parser.add_argument(
        '-H', '--host',
        type=str,
        help='Use a remote device at IP:PORT (default: 127.0.0.1:27042).'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (debug-level logging).'
    )
    parser.add_argument(
        '-p', '--perms',
        type=str,
        default="rw-",
        help="Comma-separated list of memory permissions to dump (default: 'rw-'). Example: '--perms r--,rw-,r-x'"
    )
    parser.add_argument(
        '-s', '--strings',
        action='store_true',
        help='Run "strings" on all dumped files; results go into strings.txt.'
    )
    parser.add_argument(
        '--max-size',
        type=int,
        help='Max size in bytes for each dump file (default: 20971520).',
        metavar="BYTES"
    )
    parser.add_argument(
        '--rate-limit',
        type=float,
        default=0.0,
        help='Rate limit (dumps per second). 0 means unlimited.'
    )
    parser.add_argument(
        '--auto',
        action='store_true',
        help="Automatically detect the emulator via ADB and dump its memory."
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return parser.parse_args()

# ---------------------
# Utility Functions
# ---------------------

def printProgress(current, total, prefix='', suffix='', decimals=2, bar=50):
    filled = int(round(bar * current / float(total)))
    percents = round(100.0 * (current / float(total)), decimals)
    bar_str = '#' * filled + '-' * (bar - filled)
    sys.stdout.write(f"{prefix} [{bar_str}] {percents}% {suffix}\r")
    sys.stdout.flush()
    if current == total:
        print("\n")

def strings(filename, directory, min_len=4):
    strings_file = os.path.join(directory, "strings.txt")
    path = os.path.join(directory, filename)
    try:
        with open(path, 'r', encoding='latin-1', errors='ignore') as infile:
            content = infile.read()
            str_list = re.findall(r"[A-Za-z0-9/\-:;.,_$%'!()[\]<> \#]+", content)
            with open(strings_file, "a", encoding='utf-8') as st:
                for string in str_list:
                    if len(string) >= min_len:
                        logging.debug(string)
                        st.write(string + "\n")
    except Exception as e:
        logging.debug(f"Error in strings(): {e}")

def normalize_app_name(appName):
    try:
        return int(appName)
    except (ValueError, TypeError):
        return appName.strip()

def get_emulator_ip():
    try:
        output = subprocess.check_output(["adb", "shell", "ifconfig"], universal_newlines=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing adb shell ifconfig: {e}")
        return None

    match = re.search(r"eth0\s+.*?inet addr:(\d+\.\d+\.\d+\.\d+)", output, re.DOTALL)
    if match:
        ip = match.group(1)
        logging.debug(f"IP found on eth0: {ip}")
        return ip

    match = re.search(r"wlan0\s+.*?inet addr:(\d+\.\d+\.\d+\.\d+)", output, re.DOTALL)
    if match:
        ip = match.group(1)
        logging.debug(f"IP found on wlan0: {ip}")
        return ip

    logging.error("No IP address found on eth0/wlan0 interfaces.")
    return None

def adb_forward():
    try:
        subprocess.check_call(["adb", "forward", "tcp:27042", "tcp:27042"])
        print("[*] ADB port forwarding executed: tcp:27042 -> tcp:27042")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error setting up ADB port forwarding: {e}")
        sys.exit(1)

# ---------------------
# Dump Functions
# ---------------------

def dump_to_file(agent, base, size, directory):
    filename = f"{base}_dump.data"
    outpath = os.path.join(directory, filename)
    dump = agent.readmemory(base, size)
    with open(outpath, 'wb') as f:
        f.write(dump)

def splitter(agent, base, size, max_size, directory):
    times = size // max_size
    diff = size % max_size
    cur_base = int(base, 16) if isinstance(base, str) and base.startswith("0x") else base
    for _ in range(times):
        dump_to_file(agent, cur_base, max_size, directory)
        cur_base += max_size
    if diff != 0:
        dump_to_file(agent, cur_base, diff, directory)

def run_dump(args):
    print(logo)
    debug_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format='%(levelname)s: %(message)s', level=debug_level)
    app_name = normalize_app_name(args.process)
    usb = args.usb
    ip_host = args.host if args.host else "127.0.0.1:27042"
    session_data = load_session_data(SESSION_FILE)
    dumped_ranges = session_data.get("dumped_ranges", {})
    skipped_ranges = session_data.get("skipped_ranges", {})

    if args.out:
        output_dir = args.out
        if not os.path.isdir(output_dir):
            print("[-] The specified output directory does not exist!")
            sys.exit(1)
    else:
        print("[*] No output directory specified; using './dump'.")
        output_dir = os.path.join(os.getcwd(), "dump")
        if not os.path.exists(output_dir):
            print(f"[*] Creating directory: {output_dir}")
            os.makedirs(output_dir)

    max_size = args.max_size if args.max_size else 20_971_520
    rate_limit = args.rate_limit
    run_strings_flag = args.strings
    perms_list = [p.strip() for p in args.perms.split(',')]
    logging.debug(f"Requested permissions list: {perms_list}")

    try:
        if usb:
            device = frida.get_usb_device()
            logging.debug(f"Using USB device: {device}")
            session = device.attach(app_name)
        else:
            device = frida.get_device_manager().add_remote_device(ip_host)
            logging.debug(f"Using remote device {ip_host}: {device}")
            session = device.attach(app_name)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{app_name}' not found. Please verify the name/PID.")
        sys.exit(1)
    except frida.TransportError as e:
        print(f"[-] Transport error: {e}. Check port forwarding or device connection.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

    print(f"[*] Output directory: {output_dir}")
    print(f"[*] Maximum chunk size: {max_size} bytes.")
    if rate_limit > 0:
        print(f"[*] Rate limit: {rate_limit} dumps/sec")

    # Updated JavaScript with exports in lowercase
    script_code = r"""
'use strict';

rpc.exports = {
  enumerateranges: function (prot) {
    return Process.enumerateRangesSync(prot);
  },
  readmemory: function (address, size) {
    return Memory.readByteArray(ptr(address), size);
  }
};
"""
    script = session.create_script(script_code)
    script.load()
    agent = script.exports_sync

    # Debug: print exported methods
    logging.debug("Exported methods: " + ", ".join(list(agent.__dict__.keys())))

    all_ranges = []
    for p in perms_list:
        try:
            part = agent.enumerateranges(p)
            logging.info(f"Found {len(part)} regions with permission '{p}'")
            all_ranges.extend(part)
        except Exception as e:
            logging.error(f"Unable to enumerate regions for '{p}': {e}")

    seen_bases = set()
    final_ranges = []
    for r in all_ranges:
        base = r["base"]
        if base not in seen_bases:
            seen_bases.add(base)
            final_ranges.append(r)
    final_ranges.sort(key=lambda x: x["base"])

    print(f"[*] Total unique memory regions: {len(final_ranges)}")

    i = 0
    total_ranges = len(final_ranges)
    for r in final_ranges:
        base = r["base"]
        size = r["size"]
        base_str = hex(base) if isinstance(base, int) else base.strip()
        if base_str in dumped_ranges:
            logging.debug(f"Skipping {base_str} (already dumped).")
            i += 1
            printProgress(i, total_ranges, prefix='Progress:', suffix='Complete', bar=50)
            continue
        if base_str in skipped_ranges:
            logging.debug(f"Skipping {base_str} (previous crash).")
            i += 1
            printProgress(i, total_ranges, prefix='Progress:', suffix='Complete', bar=50)
            continue
        if rate_limit > 0:
            time.sleep(1.0 / rate_limit)
        logging.debug(f"Dumping region {base_str} (size={size} bytes).")
        try:
            if size > max_size:
                splitter(agent, base, size, max_size, output_dir)
            else:
                dump_to_file(agent, base, size, output_dir)
            dumped_ranges[base_str] = True
            save_session_data(SESSION_FILE, dumped_ranges, skipped_ranges)
        except Exception as e:
            skipped_ranges[base_str] = True
            save_session_data(SESSION_FILE, dumped_ranges, skipped_ranges)
            logging.error(f"[!!!] Error dumping region {base_str}: {e}")
        i += 1
        printProgress(i, total_ranges, prefix='Progress:', suffix='Complete', bar=50)

    if run_strings_flag:
        print("[*] Running 'strings' on all dump files...")
        files_list = os.listdir(output_dir)
        j = 0
        total_files = len(files_list)
        for f1 in files_list:
            if f1.endswith(".data"):
                strings(f1, output_dir)
            j += 1
            printProgress(j, total_files, prefix='Strings:', suffix='Complete', bar=50)

    print("[*] Memory dump complete.")
    print(f"[*] Session data saved in '{SESSION_FILE}'.")
    print("[*] Regions that have already been dumped or caused a crash will be skipped in subsequent runs.")

# ---------------------
# Auto Mode
# ---------------------

def auto_mode():
    """
    Automatic mode:
      1. Use ADB to obtain the emulator IP via ifconfig.
      2. Execute port forwarding (adb forward) to map local port 27042 to the device’s port 27042.
      3. Use 127.0.0.1:27042 to connect to frida-server.
      4. List running processes and prompt the user for the target PID, the -p parameter,
         and whether to run -s strings.
      5. Start the dump.
    """
    print(logo)
    print("[*] Automatic detection mode activated.")

    ip_emulator = get_emulator_ip()
    if not ip_emulator:
        print("[-] Unable to obtain the emulator IP via ADB.")
        sys.exit(1)
    print(f"[*] Detected emulator IP: {ip_emulator}")
    
    adb_forward()
    
    host_param = "127.0.0.1:27042"
    print(f"[*] Using remote host: {host_param}")

    try:
        device = frida.get_device_manager().add_remote_device(host_param)
    except Exception as e:
        print(f"[-] Error connecting to remote device: {e}")
        sys.exit(1)

    try:
        processes = device.enumerate_processes()
    except Exception as e:
        print(f"[-] Unable to enumerate processes: {e}")
        sys.exit(1)

    print("\n[*] Running processes:")
    for proc in processes:
        if hasattr(proc, "name") and proc.name:
            print(f"PID: {proc.pid}\tApp: {proc.name}")

    target_pid = input("\nEnter the PID of the application to dump: ").strip()
    try:
        target_pid = int(target_pid)
    except ValueError:
        print("[-] The PID must be an integer.")
        sys.exit(1)

    perms = input("Enter the -p parameter (default: 'rw-'): ").strip()
    if perms == "":
        perms = "rw-"

    strings_choice = input("Do you want to run -s strings as well? (y/n, default n): ").strip().lower()
    run_strings_flag = True if strings_choice == "y" else False

    class Args:
        pass
    auto_args = Args()
    auto_args.process = target_pid
    auto_args.out = None
    auto_args.usb = False
    auto_args.host = host_param
    auto_args.verbose = False
    auto_args.perms = perms
    auto_args.strings = run_strings_flag
    auto_args.max_size = None
    auto_args.rate_limit = 0.0
    auto_args.auto = False

    print("\n[*] Starting dump in automatic mode...\n")
    run_dump(auto_args)

# ---------------------
# Main Script
# ---------------------

def main():
    args = MENU()
    if args.auto:
        auto_mode()
    else:
        if not args.process:
            print("[-] Please specify the target process name or PID, or use the --auto flag for automatic detection.")
            sys.exit(1)
        run_dump(args)

if __name__ == "__main__":
    main()
