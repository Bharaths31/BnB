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
    """Stop this project's containers but keep them (resume later with `start`)."""
    print("Stopping this project's containers...")
    run("docker compose stop")


def stop_all():
    """Stop and remove all containers created by *this* project only.

    Scoped to the compose project (`docker compose down --remove-orphans`) so unrelated
    containers on the machine are never touched. Data volumes are preserved (use
    `docker compose down -v` manually if you want to wipe state).
    """
    print("Stopping and removing all containers created by this project...")
    run("docker compose down --remove-orphans")


def status_docker():
    print("Docker Compose status:")
    run("docker compose ps")


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


def verify_system():
    print("Verifying that phishing is detected and blocked...")
    run(f'"{sys.executable}" scripts/verify.py')


def session_log():
    print("Starting the independent Docker session logger (Ctrl+C to finish)...")
    run(f'"{sys.executable}" scripts/session_logger.py --start')


def main():
    parser = argparse.ArgumentParser(description="PhishGuard Manager")
    parser.add_argument(
        "action",
        choices=[
            "start", "stop", "stop_all", "status", "setup_models", "demo",
            "verify", "session_log", "setup_all",
        ],
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
    elif args.action == "verify":
        verify_system()
    elif args.action == "session_log":
        session_log()
    elif args.action == "setup_all":
        start_docker()
        setup_models()
        run_demo()
        print("Setup complete! Visit http://localhost:3000 to see the dashboard.")


if __name__ == "__main__":
    main()
