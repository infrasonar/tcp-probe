import asyncio
import os
import subprocess
from libprobe.exceptions import CheckException

DEFAULT_MAX_WORKERS = (os.cpu_count() or 1) * 5
SEMAPHORE = asyncio.Semaphore(value=DEFAULT_MAX_WORKERS)


async def run(params):
    async with SEMAPHORE:
        max_runtime = 60  # 60 seconds
        try:
            state_data = await asyncio.wait_for(
                run_cmd(params),
                timeout=max_runtime
            )
        except CheckException:
            raise
        except asyncio.TimeoutError:
            raise CheckException('Nmap timed out')
        except subprocess.CalledProcessError as e:
            raise CheckException(f'Error: {e.returncode}, {e.stderr}')
        except FileNotFoundError:
            raise CheckException('Nmap not installed in system')
        except Exception as e:
            msg = str(e) or type(e).__name__
            raise CheckException(msg)
        else:
            return state_data


async def run_cmd(params):
    process = await asyncio.create_subprocess_exec(
        *params,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        msg = stderr.decode().strip() or 'missing error output'
        raise CheckException(
                f'Params={params}, pid={process.pid}, output={msg}')

    return stdout
