#!/usr/bin/env python3
"""Stages used by the checksum-bound disposable migration lifecycle."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = json.loads((ROOT / '.ai/testing/provisioners/auth-postgres-migration.v1.json').read_text())


def run(args, timeout=60, owner_parent=None):
    # Register the owned child before accepting cancellation. Its Docker CLI
    # group must be stopped and reaped before harness resource cleanup starts.
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    child = None
    try:
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True,
                                 preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        deadline = time.monotonic() + timeout
        while True:
            if owner_parent is not None:
                try:
                    os.kill(owner_parent, 0)
                except ProcessLookupError:
                    raise RuntimeError('Migration invocation parent exited')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(args, timeout)
            try:
                stdout, stderr = child.communicate(timeout=min(.2, remaining) if owner_parent else remaining)
                break
            except subprocess.TimeoutExpired:
                if owner_parent is None:
                    raise
        if child.returncode:
            raise subprocess.CalledProcessError(child.returncode, args, stdout, stderr)
        return stdout.strip()
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate(timeout=5)
            # A CLI leader can exit before its Compose plugin descendants.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        raise
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def cancelled(signum, frame):
    raise RuntimeError('Owned migration provisioner was cancelled')


def main():
    stage = sys.argv[1]
    if stage == 'image':
        print(DESCRIPTOR['images'][0]['reference'])
        return
    if stage == 'verify':
        versions = {
            'Docker Engine': run(['docker', 'version', '--format', '{{.Server.Version}}'], 8),
            'Docker Compose': run(['docker', 'compose', 'version', '--short'], 8),
        }
        for tool in DESCRIPTOR['toolchain']:
            if versions[tool['name']].removeprefix('v') != tool['version']:
                raise RuntimeError(f"{tool['name']} version differs from provisioner contract")
        return
    project = os.environ['COMPOSE_PROJECT_NAME']
    compose = Path(os.environ['COMPOSE_FILE'])
    if not re.fullmatch(r'auth-migration-test-[a-z0-9-]+-(local|prod|legacy)', project) or not compose.is_file():
        raise RuntimeError('Disposable migration stage requires its owned project and generated Compose file')
    args = ['docker', 'compose', '-p', project, '-f', str(compose)]
    if stage == 'execute':
        parent = int(os.environ['AUTH_MIGRATION_HARNESS_PARENT_PID'])
        if parent <= 1 or not sys.argv[2:]:
            raise RuntimeError('Owned migration command requires its invocation parent and argv')
        result = run(sys.argv[2:], owner_parent=parent)
        if result:
            print(result)
    elif stage == 'start':
        run(args + ['up', '-d', 'postgres'])
    elif stage == 'cleanup':
        run(args + ['down', '-v', '--remove-orphans'])
    elif stage == 'readiness':
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                result = run(args + ['exec', '-T', 'postgres', 'psql', '-X', '-U', 'app', '-d', 'authdb', '-v', 'ON_ERROR_STOP=1', '-tAc', 'SELECT 1'], min(2, max(.1, deadline - time.monotonic())))
                if result == '1':
                    return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise RuntimeError('Disposable PostgreSQL did not return SELECT 1 within 60 seconds')
    else:
        raise RuntimeError('Unknown migration provisioner stage')


if __name__ == '__main__':
    signal.signal(signal.SIGINT, cancelled)
    signal.signal(signal.SIGTERM, cancelled)
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stdout:
            sys.stdout.write(error.stdout)
        if error.stderr:
            sys.stderr.write(error.stderr)
        print(f'migration provisioner command exited with status {error.returncode}', file=sys.stderr)
        sys.exit(1)
    except (KeyError, ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f'migration provisioner failed: {error}', file=sys.stderr)
        sys.exit(1)
