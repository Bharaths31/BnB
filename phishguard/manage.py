#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys

def run(cmd, **kwargs):
    print(f"Running: {cmd}")
    subprocess.check_call(cmd, shell=True, **kwargs)

def start_docker():
    print("Starting Docker containers...")
    run("docker compose up -d")

def stop_docker():
    print("Stopping Docker containers...")
    run("docker compose down")

def setup_models():
    print("Exporting ONNX models inside the backend container...")
    # Read the script and pipe it to docker exec
    with open("scripts/download_models.py", "r") as f:
        script_content = f.read()
    
    # Run the script inside the backend container
    process = subprocess.Popen(["docker", "exec", "-i", "phishguard-backend", "python3"], stdin=subprocess.PIPE)
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
    parser.add_argument("action", choices=["start", "stop", "setup_models", "demo", "setup_all"])
    args = parser.parse_args()
    
    # Change to project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    if args.action == "start":
        start_docker()
    elif args.action == "stop":
        stop_docker()
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
