import asyncio
import os
import subprocess

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
        except asyncio.TimeoutError:
            raise Exception('Check timed out.')
        except subprocess.CalledProcessError as e:
            raise Exception(f'Error: {e.returncode}, {e.stderr}')
        except FileNotFoundError:
            raise Exception('Nmap not installed in system')
        except Exception as e:
            raise Exception(f'Check error: {e.__class__.__name__}: {e}')
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
        raise Exception(
            (
                f'Failed: {params}, pid={process.pid}, '
                f'result: {stderr.decode().strip()}'
            ),
            flush=True,
        )

    return stdout
