import argparse
import time
import os
import binascii
import ctypes
import multiprocessing
import nacl.signing
from rich.console import Console
from rich.live import Live
from rich.text import Text
from .client import Session
from .mnemonic import encode as encode_mnemonic, decode as decode_mnemonic

def format_time(seconds: float) -> str:
    if seconds <= 0:
        return "0s"
    MINUTE = 60
    HOUR = 3600
    DAY = 86400
    MONTH = 2592000  # 30 days
    YEAR = 31536000  # 365 days
    
    if seconds < MINUTE:
        return f"{seconds:.0f}s"
    if seconds < HOUR:
        m = int(seconds // MINUTE)
        s = int(seconds % MINUTE)
        return f"{m}m {s}s"
    if seconds < DAY:
        h = int(seconds // HOUR)
        m = int((seconds % HOUR) // MINUTE)
        return f"{h}h {m}m"
    if seconds < MONTH:
        d = int(seconds // DAY)
        h = int((seconds % DAY) // HOUR)
        return f"{d}d {h}h"
    if seconds < YEAR:
        mo = int(seconds // MONTH)
        d = int((seconds % MONTH) // DAY)
        return f"{mo}mo {d}d"
        
    y = int(seconds // YEAR)
    mo = int((seconds % YEAR) // MONTH)
    return f"{y}y {mo}mo"

def search_worker(prefix: str, result_queue: multiprocessing.Queue, checked_counter: multiprocessing.Value, stop_event: multiprocessing.Event):
    """
    Worker process for brute-forcing vanity Session IDs.
    """
    import os
    import binascii
    import nacl.signing
    from .mnemonic import encode as encode_mnemonic
    
    local_checked = 0
    while not stop_event.is_set():
        local_checked += 1
        seed_16 = os.urandom(16)
        
        # Derive Session ID
        seed_32_hex = binascii.hexlify(seed_16).decode('utf-8') + "00000000000000000000000000000000"
        seed_32 = binascii.unhexlify(seed_32_hex)
        
        signing_key = nacl.signing.SigningKey(seed_32)
        x25519_pub = signing_key.verify_key.to_curve25519_public_key()
        session_id = "05" + x25519_pub.encode().hex()
        
        if session_id[2:].startswith(prefix):
            mnemonic = encode_mnemonic(binascii.hexlify(seed_16).decode('utf-8'))
            result_queue.put((session_id, mnemonic))
            stop_event.set()
            break
            
        # Update shared counter periodically to avoid locking bottleneck
        if local_checked >= 2000:
            with checked_counter.get_lock():
                checked_counter.value += local_checked
            local_checked = 0
            
    if local_checked > 0:
        with checked_counter.get_lock():
            checked_counter.value += local_checked

def main():
    multiprocessing.freeze_support()
    
    max_threads = os.cpu_count() or 1
    
    parser = argparse.ArgumentParser(
        description="Session Python CLI - Command Line interface for Session Messenger"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")
    
    # 'mnemonic' group command
    mnemonic_parser = subparsers.add_parser("mnemonic", help="Mnemonic and account key utilities")
    mnemonic_subparsers = mnemonic_parser.add_subparsers(dest="subcommand", help="Sub-commands of mnemonic")
    
    # 'mnemonic verify'
    verify_parser = mnemonic_subparsers.add_parser("verify", help="Verify a 13-word mnemonic")
    verify_parser.add_argument("words", type=str, help="The 13-word mnemonic to verify")
    
    # 'mnemonic gen'
    gen_parser = mnemonic_subparsers.add_parser("gen", help="Generate new mnemonics or derive ID from existing mnemonic")
    gen_parser.add_argument("words", type=str, nargs="?", default=None, help="Optional existing 13-word mnemonic to derive ID from")
    gen_parser.add_argument(
        "-n",
        type=int,
        default=1,
        help="Number of accounts to generate (1 to 100)"
    )
    gen_parser.add_argument(
        "-p", "--prefix",
        type=str,
        default="",
        help="Prefix the generated Session ID must start with (after 05, hex only, e.g. 'abc')"
    )
    gen_parser.add_argument(
        "-t", "--threads",
        type=int,
        default=0,
        help=f"Number of CPU threads to use (1 to {max_threads}, 0 for all cores, default: 0)"
    )
    
    args = parser.parse_args()
    console = Console()
    
    if args.command == "mnemonic":
        if args.subcommand == "verify":
            words = args.words.strip()
            try:
                seed_hex = decode_mnemonic(words)
                # Derive Session ID
                session = Session()
                session.set_mnemonic(words)
                session_id = session.get_session_id()
                console.print("[bold green]Valid Mnemonic![/bold green]")
                console.print(f"Session ID: {session_id}")
                console.print(f"Hex Seed:   {seed_hex}")
            except ValueError as e:
                console.print(f"[bold red]Invalid Mnemonic:[/bold red] {e}")
                
        elif args.subcommand == "gen":
            words = args.words.strip() if args.words else None
            
            if words:
                # Derive Session ID for provided mnemonic
                try:
                    session = Session()
                    session.set_mnemonic(words)
                    session_id = session.get_session_id()
                    console.print(f"{session_id} - {words}")
                except ValueError as e:
                    console.print(f"[bold red]Error deriving ID:[/bold red] {e}")
            else:
                # Generate new accounts (vanity search or instant)
                count = args.n
                if count < 1 or count > 100:
                    parser.error("The number of accounts (-n) must be between 1 and 100.")
                    
                threads_arg = args.threads
                if threads_arg < 0 or threads_arg > max_threads:
                    parser.error(f"The number of threads (-t/--threads) must be between 0 and {max_threads} (your CPU has {max_threads} cores).")
                    
                num_workers = max_threads if threads_arg == 0 else threads_arg
                
                prefix = args.prefix.lower() if args.prefix else ""
                if prefix:
                    if not all(c in "0123456789abcdef" for c in prefix):
                        parser.error("The prefix (-p/--prefix) must contain only valid hex characters (0-9, a-f).")
                        
                for _ in range(count):
                    if prefix:
                        start_time = time.time()
                        total_expected = 16 ** len(prefix)
                        
                        # Shared resources for multiprocessing
                        result_queue = multiprocessing.Queue()
                        checked_counter = multiprocessing.Value(ctypes.c_uint64, 0)
                        stop_event = multiprocessing.Event()
                        
                        # Spawn workers
                        processes = []
                        for _ in range(num_workers):
                            p = multiprocessing.Process(
                                target=search_worker,
                                args=(prefix, result_queue, checked_counter, stop_event)
                            )
                            p.daemon = True
                            p.start()
                            processes.append(p)
                        
                        if console.is_terminal:
                            with Live(Text("Initializing search...", style="yellow"), refresh_per_second=10, transient=True) as live:
                                while not stop_event.is_set() and result_queue.empty():
                                    time.sleep(0.1)
                                    checked = checked_counter.value
                                    elapsed = time.time() - start_time
                                    speed = checked / elapsed if elapsed > 0 else 0
                                    
                                    if checked < total_expected:
                                        remaining_checks = total_expected - checked
                                        remaining_seconds = remaining_checks / speed if speed > 0 else 0
                                        eta_str = format_time(remaining_seconds)
                                    else:
                                        avg_seconds = total_expected / speed if speed > 0 else 0
                                        eta_str = f"running over (avg {format_time(avg_seconds)})"
                                    
                                    live.update(Text(
                                        f"Searching for ID starting with '05{prefix}' ({num_workers} threads)...\n"
                                        f"Speed: {speed:.1f} id/sec | Checked: {checked}/{total_expected} | Time: {elapsed:.1f}s | ETA: {eta_str}",
                                        style="cyan"
                                    ))
                        else:
                            # Run silently in non-TTY mode (e.g. wrapped by setuptools exe or redirected)
                            while not stop_event.is_set() and result_queue.empty():
                                time.sleep(0.1)
                        
                        # Retrieve result and cleanup processes
                        session_id, mnemonic = result_queue.get()
                        for p in processes:
                            if p.is_alive():
                                p.terminate()
                        
                        console.print(f"[bold green]{session_id}[/bold green] - [bold white]{mnemonic}[/bold white]")
                    else:
                        # Instant generation without prefix
                        mnemonic = Session.generate_mnemonic()
                        session = Session()
                        session.set_mnemonic(mnemonic)
                        session_id = session.get_session_id()
                        console.print(f"[bold green]{session_id}[/bold green] - [bold white]{mnemonic}[/bold white]")
        else:
            mnemonic_parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
