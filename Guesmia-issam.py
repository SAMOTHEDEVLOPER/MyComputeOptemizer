#!/usr/bin/env python3
import os
import subprocess
import sys
import time

# --- Configuration ---

# The target Bitcoin address for the search.
TARGET_ADDRESS = "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"

# The hexadecimal keyspace range for the sequential search. Format: "START:END"
RANGE_VALUE = "101D83275000000000:101D83275FFFFFFFFF"

# The name of the compiled binary to be executed.
BINARY_NAME = "ComputeUnitOptimizer"

# File to store the output of found keys.
OUTPUT_FILE = "Found.txt"

# --- GitHub Repository Configuration ---
# It is STRONGLY recommended to set your credentials as environment variables
# rather than hardcoding them here.
# Example:
# export GITHUB_USERNAME="YourUsername"
# export GITHUB_PAT="YourPersonalAccessToken"
GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME", "SAMOTHEDEVLOPER")
GITHUB_PAT = os.environ.get("GITHUB_PAT")

# Security Warning: Avoid hardcoding your PAT. The fallback value is for demonstration only.
if not GITHUB_PAT:
    print("Warning: GITHUB_PAT environment variable not set. Using a potentially expired hardcoded token.", file=sys.stderr)
    GITHUB_PAT = "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"

# Construct the authenticated URL for the private repository.
REPO_URL = f"https://{GITHUB_USERNAME}:{GITHUB_PAT}@github.com/SAMOTHEDEVLOPER/MyComputeOptemizer.git"
REPO_DIR = "MyComputeOptemizer"

# The C++ project is located in a subdirectory of the repository.
BUILD_DIR = os.path.join(REPO_DIR, "ComputeUnitOptimizer-Cuda")


def install_dependencies():
    """
    Installs required system dependencies using apt-get.
    Note: This is designed for Debian-based systems like Ubuntu.
    """
    print("--> Installing required dependencies...")
    try:
        # Update package lists and install the GMP development library.
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "install", "-y", "libgmp-dev"], check=True)
        print("Dependencies installed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error: Failed to install dependencies: {e}", file=sys.stderr)
        print("Please ensure you are running on a Debian-based system and have root/sudo privileges.", file=sys.stderr)
        sys.exit(1)


def clone_repo():
    """Clones the private GitHub repository if it doesn't already exist."""
    if os.path.exists(REPO_DIR):
        print(f"--> Repository '{REPO_DIR}' already exists. Skipping clone.")
        return

    print(f"--> Cloning private repository...")
    try:
        subprocess.run(["git", "clone", REPO_URL], check=True, capture_output=True)
        print("Repository cloned successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to clone repository: {e}", file=sys.stderr)
        print(f"STDOUT: {e.stdout.decode()}", file=sys.stderr)
        print(f"STDERR: {e.stderr.decode()}", file=sys.stderr)
        print("Please check your GitHub credentials and repository URL.", file=sys.stderr)
        sys.exit(1)


def build_binary():
    """
    Builds the C++ binary with GPU support using the project's Makefile.
    This function changes the current directory to the build directory and then returns.
    """
    if not os.path.exists(BUILD_DIR):
        print(f"Error: Build directory '{BUILD_DIR}' not found.", file=sys.stderr)
        sys.exit(1)

    print(f"--> Building '{BINARY_NAME}' in '{BUILD_DIR}'...")
    # The Makefile requires specific variables for a GPU build.
    # CCAP=75 targets NVIDIA Turing architecture (e.g., RTX 20 series). Adjust if needed.
    make_cmd = ["make", "-f", "Makefile", "CUDA=/usr/local/cuda", "gpu=1", "CCAP=75", "all"]

    try:
        # We change into the build directory to run make, as is standard practice.
        original_dir = os.getcwd()
        os.chdir(BUILD_DIR)
        
        # Run the build command, capturing output for debugging.
        result = subprocess.run(make_cmd, check=True, capture_output=True, text=True)
        print(f"Build successful!\n{result.stdout}")

    except subprocess.CalledProcessError as e:
        print("Error: Build failed.", file=sys.stderr)
        print(f"--- STDOUT ---\n{e.stdout}", file=sys.stderr)
        print(f"--- STDERR ---\n{e.stderr}", file=sys.stderr)
        sys.exit(1)
    finally:
        # Ensure we return to the original directory.
        os.chdir(original_dir)


def run_search():
    """
    Executes the compiled binary to start the key search and captures results.
    It streams the output in real-time and saves any found key blocks to OUTPUT_FILE.
    """
    bin_path = os.path.join(BUILD_DIR, BINARY_NAME)
    if not os.path.exists(bin_path):
        print(f"Error: Binary '{bin_path}' not found. Please build it first.", file=sys.stderr)
        sys.exit(1)

    # Command-line arguments for the search tool.
    cmd = [
        bin_path,
        "-g",                     # Enable GPU computation.
        "-m", "ADDRESS",          # Set mode to search for a single Bitcoin address.
        "--gpui", "0",            # Use GPU device 0.
        "--gpux", "1024,512",     # Set GPU grid/block dimensions.
        "--range", RANGE_VALUE,   # Provide the sequential keyspace range.
        TARGET_ADDRESS            # The target address itself.
    ]

    print("--> Executing search command:")
    print("    " + " ".join(cmd))
    print("-" * 40)

    start_time = time.time()
    try:
        # Use Popen for real-time output streaming.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        
        # Open the output file in append mode to preserve previous results.
        with open(OUTPUT_FILE, "a") as out_file:
            # State machine to capture blocks of text delimited by "====" lines.
            capturing_block = False
            candidate_block = []

            for line in proc.stdout:
                line_stripped = line.strip()
                print(line_stripped)  # Print all output for live monitoring.

                if line_stripped.startswith("=" * 10):
                    if capturing_block:
                        # This is the end of a block.
                        candidate_text = "\n".join(candidate_block)
                        
                        # Filter out known error messages to avoid saving false positives.
                        if "wrong private key generated" not in candidate_text:
                            print("\n--- Candidate Key Block Found! Writing to file. ---\n")
                            out_file.write(candidate_text + "\n" + "="*80 + "\n\n")
                            out_file.flush()
                        
                        # Reset for the next block.
                        capturing_block = False
                        candidate_block = []
                    else:
                        # This is the start of a block.
                        capturing_block = True
                elif capturing_block:
                    candidate_block.append(line_stripped)

    except FileNotFoundError:
        print(f"Error: Command not found at '{bin_path}'.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n--> Search interrupted by user.")
    finally:
        if 'proc' in locals() and proc.poll() is None:
            proc.terminate() # Ensure the process is stopped.
        end_time = time.time()
        print("-" * 40)
        print(f"Search process finished in {end_time - start_time:.2f} seconds.")


def main():
    """Main function to run the setup and search workflow."""
    install_dependencies()
    clone_repo()
    build_binary()
    run_search()


if __name__ == '__main__':
    main()
