#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys


def run(cmd, **kwargs):
    print(f"Running: {cmd}")
    subprocess.check_call(cmd, shell=True, **kwargs)


def start_docker():
    print("Starting Docker containers...")
    run("docker compose up -d")


def stop_docker():
    print("Stopping Docker containers (this project)...")
    run("docker compose down")


def status_docker():
    print("Docker Compose status:")
    run("docker compose ps")


def _running_container_ids():
    """Return the IDs of every running Docker container (system-wide)."""
    try:
        out = subprocess.check_output(["docker", "ps", "-q"], text=True).strip()
    except Exception as exc:  # docker missing or daemon not running
        print(f"Could not query Docker: {exc}")
        return []
    return out.split()


def stop_all():
    """Stop ALL Docker containers that have been started.

    1. Tear down this project's compose stack (containers + network).
    2. Stop any other running containers on the machine.
    """
    print("Stopping the PhishGuard compose stack...")
    try:
        run("docker compose down --remove-orphans")
    except subprocess.CalledProcessError:
        print("docker compose down failed or the stack was not running; continuing.")

    ids = _running_container_ids()
    if not ids:
        print("No running Docker containers remain.")
        return
    print(f"Stopping {len(ids)} remaining running container(s)...")
    subprocess.check_call(["docker", "stop", *ids])
    print("All running Docker containers stopped.")


def setup_models():
    print("Exporting ONNX models inside the backend container...")
    # Read the script and pipe it to docker exec
    with open("scripts/download_models.py", "r") as f:
        script_content = f.read()

    # Run the script inside the backend container
    process = subprocess.Popen(
        ["docker", "exec", "-i", "phishguard-backend", "python3"], stdin=subprocess.PIPE
    )
    process.communicate(input=script_content.encode())
    if process.returncode != 0:
        print("Failed to download models.")
        sys.exit(1)

    # Restart backend to load the models
    run("docker compose restart backend")
    print("ONNX models are ready and backend restarted.")


def run_demo():
    print("Sending demo emails...")
    run("bash scripts/setup_demo.sh")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard Manager")
    parser.add_argument(
        "action",
        choices=["start", "stop", "stop_all", "status", "setup_models", "demo", "setup_all"],
    )
    args = parser.parse_args()

    # Change to project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    if args.action == "start":
        start_docker()
    elif args.action == "stop":
        stop_docker()
    elif args.action == "stop_all":
        stop_all()
    elif args.action == "status":
        status_docker()
    elif args.action == "setup_models":
        setup_models()
    elif args.action == "demo":
        run_demo()
    elif args.action == "setup_all":
        start_docker()
        setup_models()
        run_demo()
        print("Setup complete! Visit http://localhost:3000 to see the dashboard.")


if __name__ == "__main__":
    main()
