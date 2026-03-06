# Ghost Protocol - Command Execution Fixes

## Problem Identified
Commands like `ls`, `dir`, `ip a`, and other basic Linux commands were not working in the SSH honeypot. The issue was in the command routing logic.

## Root Cause
The SSH server (`gateway/ssh_server.py`) was checking for built-in commands using `handle_builtin_command()` from `ssh_presentation.py`, but this function only handled a limited set of commands:
- `whoami`
- `hostname`
- `pwd`
- `uname -a`

Commands like `ls`, `dir`, `ip a`, `ifconfig`, `id`, `echo`, `date`, and `uptime` were not recognized as built-in commands, so they were being routed to the AI pipeline. However, the response generator had the logic to handle these commands but it was never being called because the commands were failing earlier in the pipeline.

## Solution Applied

### 1. Enhanced `ssh_presentation.py` - `handle_builtin_command()`
Added support for additional built-in commands that should be handled immediately without going through the AI pipeline:

**New commands supported:**
- `id` - User identity (returns `uid=0(root) gid=0(root) groups=0(root)`)
- `ip a`, `ip addr`, `ip address` - Network interface information
- `ifconfig` - Legacy network interface info
- `echo` - Print arguments
- `date` - Current date/time
- `uptime` - System uptime
- `uname` variants - All uname options (already existed, enhanced)

These commands now return immediately without going through the AI pipeline, providing instant responses.

### 2. Fixed `response_generator.py` - Directory Listing Detection
**Changed:** `_detect_directory_listing()` method
- **Before:** Returned `(None, False)` when no path was specified
- **After:** Returns `("", False)` for current directory, allowing `ls` and `dir` without arguments to work

**Changed:** `_generate_directory_listing()` method
- **Before:** Used fallback logic from `session_state.fake_fs`
- **After:** Properly normalizes paths and uses `format_directory_listing()` from `bait_files.py` for consistent output

**Changed:** `_read_file_content()` method
- **Before:** Had complex fallback logic
- **After:** Simplified to use `get_bait_content()` from `bait_files.py` with proper path normalization

### 3. Command Routing Flow (Now Fixed)

```
SSH Command Input
    ↓
Check ssh_presentation.py built-ins (whoami, pwd, hostname, id, uname, ip, ifconfig, echo, date, uptime)
    ↓ (if not found)
Route to response_generator.py
    ↓
Check for directory listing (ls, dir with all flags)
    ↓ (if not found)
Check for file access (cat, less, more, head, tail, grep, etc.)
    ↓ (if not found)
Route to AI pipeline (LLM for advanced commands)
```

## Files Modified

1. **`gateway/ssh_presentation.py`**
   - Enhanced `handle_builtin_command()` with 8 new command types
   - All commands now return proper output immediately

2. **`ai_core/response_generator.py`**
   - Fixed `_detect_directory_listing()` to handle empty path (current directory)
   - Improved `_generate_directory_listing()` to use bait_files module
   - Simplified `_read_file_content()` with proper path normalization

## Testing Commands

Now these commands should work correctly:

```bash
# Basic commands (handled by ssh_presentation.py)
whoami              # Returns: root
pwd                 # Returns: /root
hostname            # Returns: ip-<ip-address>
id                  # Returns: uid=0(root) gid=0(root) groups=0(root)
uname -a            # Returns: Full kernel info
ip a                # Returns: Network interfaces
ifconfig            # Returns: Network config
echo "hello"        # Returns: hello
date                # Returns: Thu Mar  6 14:23:15 UTC 2026
uptime              # Returns: System uptime

# Directory listing (handled by response_generator.py)
ls                  # Lists current directory
ls -la              # Lists with long format
ls /root            # Lists specific directory
dir                 # Same as ls
dir -la /home/admin # Lists with long format

# File access (handled by response_generator.py)
cat /root/.aws/credentials      # Returns: AWS credentials (triggers threat detection)
cat /home/admin/passwords.txt   # Returns: Password file (triggers threat detection)
cat /var/backups/customer_db.sql # Returns: Database backup (triggers threat detection)
```

## Performance Impact

- **Faster response times** for basic commands (no LLM inference needed)
- **Reduced LLM load** by handling deterministic commands locally
- **Consistent output** using the bait_files module for filesystem operations
- **Better threat detection** for credential access patterns

## Backward Compatibility

All changes are backward compatible. The command routing is now more efficient but maintains the same threat intelligence pipeline for credential detection and MITRE mapping.
