import time
import subprocess

def main():
    user_id = input("Введите айди: ")
    
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
        subprocess.run(command, shell=True)  # Реальный ввод команды в терминал
        time.sleep(0.5)  # Небольшая задержка для стабильности

if __name__ == "__main__":
    main()
