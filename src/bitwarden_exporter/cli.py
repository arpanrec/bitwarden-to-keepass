import os
import os.path
import subprocess  # nosec B404
from typing import List, Optional, Dict

from cachier import cachier

from src.bitwarden_exporter import BitwardenException


@cachier()
def bw_exec(cmd: List[str], ret_encoding: str = "UTF-8", env_vars: Optional[Dict[str, str]] = None) -> str:
    """
    Executes a Bitwarden CLI command and returns the output as a string.
    """
    cmd = ["bw"] + cmd + ["--raw"]

    cli_env_vars = os.environ

    if env_vars is not None:
        cli_env_vars.update(env_vars)
    print(f"Executing CLI :: {' '.join(cmd)}")
    command_out = subprocess.run(
        cmd, capture_output=True, check=False, encoding=ret_encoding, env=cli_env_vars
    )  # nosec B603
    if len(command_out.stderr) > 0:
        raise BitwardenException(f"Error in executing command {command_out.stderr}")
    command_out.check_returncode()
    if len(command_out.stdout) > 0:
        return command_out.stdout

    return ""
