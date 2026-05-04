# -*- coding: utf-8 -*-
"""
BitNet — Local Password Manager CLI
"""
import asyncio
import getpass
import sys
from typing import Optional

# Requires installing rich and pyperclip
try:
    from rich.console import Console
    from rich.table import Table
    import pyperclip
except ImportError:
    print("Please install rich and pyperclip: pip install rich pyperclip")
    sys.exit(1)

# Ensure local config and logging gets imported without issues.
from backend.database.session import async_engine, get_db, init_db
from backend.database.entry_service import EntryService
from backend.core.encryption_helper import EncryptionHelper
from backend.core.crypto_core import CryptoCore, zero_memory

console = Console()

async def clear_clipboard_after_delay(delay_seconds: int = 30) -> None:
    """Clear the clipboard after a prescribed delay."""
    await asyncio.sleep(delay_seconds)
    pyperclip.copy("")
    console.print("\n[yellow]Clipboard cleared for security.[/yellow]")

async def unlock_vault() -> Optional[bytearray]:
    master_password = getpass.getpass("Master Password: ")
    # For a real implementation, authenticate and extract derived master key
    # returning that key for operations
    # Here we emulate returning a dummy derived key
    console.print("[green]Vault unlocked![/green]")
    # Emulate:
    crypto = CryptoCore()
    salt = crypto.generate_salt() # normally load from db
    derived = bytearray(crypto.derive_master_key(master_password, salt))
    return derived # Caller must zero

async def main() -> None:
    if len(sys.argv) < 2:
        console.print("Usage: bitnet [init|list|get|add]")
        return
        
    cmd = sys.argv[1]
    
    if cmd == "init":
        init_db()
        console.print("[green]Local database initialized![/green]")
        return
        
    master_key = await unlock_vault()
    if not master_key:
        return
        
    try:
        if cmd == "list":
            # Just an example loop
            table = Table(title="Vault Entries")
            table.add_column("ID", justify="right", style="cyan")
            table.add_column("Title", style="magenta")
            console.print(table)
            
        elif cmd == "get":
            if len(sys.argv) < 3:
                console.print("Providing ID is required")
                return
            
            # Fetch, decrypt raw, copy to clipboard
            pyperclip.copy("dummy_password_from_db")
            console.print("[green]Password copied to clipboard! Will clear in 30 seconds.[/green]")
            await clear_clipboard_after_delay(30)
            
        else:
            console.print(f"Unknown command {cmd}")
            
    finally:
        zero_memory(master_key)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting. Memory wiped.[/yellow]")
        sys.exit(0)
