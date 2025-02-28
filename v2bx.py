import subprocess

def main():
    user_id = input("Введите ID: ")
    
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
    
    process = subprocess.Popen(["/bin/bash"], stdin=subprocess.PIPE, text=True)
    for cmd in commands:
        process.stdin.write(cmd + "\n")
    process.stdin.close()
    process.wait()

if __name__ == "__main__":
    main()
