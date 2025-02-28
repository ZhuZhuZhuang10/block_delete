import time
import subprocess
import sys

def main():
    if len(sys.argv) < 2:
        print("Использование: python3 script.py <айди>")
        sys.exit(1)
    
    user_id = sys.argv[1]

    commands = [
        "v2bx",
        "15",
        "y",
        "https://bibihy-shop.org",
        "imlalaimlalaimlala",
        "y",
        "1",
        user_id,
        "2",
        "y",
        "n"
    ]
    
    for command in commands:
        subprocess.run(command, shell=True)
        time.sleep(0.5)

if __name__ == "__main__":
    main()
