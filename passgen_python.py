# passgen_python.py — генератор паролей с настраиваемыми правилами на Python

import random
import string
import argparse
import sys
import math
import os
import json
from secrets import choice as secrets_choice

class PasswordGenerator:
    def __init__(self):
        self.config_file = "passgen_config.json"
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                "default_length": 16,
                "use_letters": True,
                "use_digits": True,
                "use_special": True,
                "exclude_similar": False,
                "exclude_ambiguous": False
            }

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def generate_password(self, length, use_letters, use_digits, use_special,
                           exclude_similar, exclude_ambiguous):
        chars = ""
        if use_letters:
            chars += string.ascii_letters
        if use_digits:
            chars += string.digits
        if use_special:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"

        if exclude_similar:
            similar = "O0Il1"
            for c in similar:
                chars = chars.replace(c, '')
        if exclude_ambiguous:
            ambiguous = "{}[]()/\\\"'`~,;:.<>"
            for c in ambiguous:
                chars = chars.replace(c, '')

        if not chars:
            raise ValueError("Нет доступных символов для генерации")

        # Используем криптостойкий генератор
        password = ''.join(secrets_choice(chars) for _ in range(length))
        return password

    def entropy(self, password):
        # Подсчёт энтропии (бит)
        chars_set = set(password)
        entropy_per_char = math.log2(len(chars_set))
        return entropy_per_char * len(password)

    def crack_time(self, entropy):
        # Оценка времени взлома (в годах, при 10^9 паролей/сек)
        guesses = 2 ** entropy
        seconds = guesses / 1e9
        years = seconds / (60 * 60 * 24 * 365.25)
        return years

    def run_interactive(self):
        print("🔐 PassGen Pro — Python Edition")
        print("Настройка параметров (можно оставить пустым для использования значений по умолчанию):")
        length = input(f"Длина пароля (по умолчанию {self.config['default_length']}): ")
        if length.strip():
            self.config['default_length'] = int(length)
        use_letters = input("Использовать буквы? (y/n, по умолчанию y): ").strip().lower()
        if use_letters == 'n':
            self.config['use_letters'] = False
        use_digits = input("Использовать цифры? (y/n, по умолчанию y): ").strip().lower()
        if use_digits == 'n':
            self.config['use_digits'] = False
        use_special = input("Использовать специальные символы? (y/n, по умолчанию y): ").strip().lower()
        if use_special == 'n':
            self.config['use_special'] = False
        excl_similar = input("Исключить похожие символы? (y/n, по умолчанию n): ").strip().lower()
        self.config['exclude_similar'] = excl_similar == 'y'
        excl_ambiguous = input("Исключить двусмысленные символы? (y/n, по умолчанию n): ").strip().lower()
        self.config['exclude_ambiguous'] = excl_ambiguous == 'y'
        count = input("Количество паролей (по умолчанию 1): ")
        count = int(count) if count.strip() else 1

        self.save_config()

        for i in range(count):
            try:
                pwd = self.generate_password(
                    self.config['default_length'],
                    self.config['use_letters'],
                    self.config['use_digits'],
                    self.config['use_special'],
                    self.config['exclude_similar'],
                    self.config['exclude_ambiguous']
                )
                ent = self.entropy(pwd)
                years = self.crack_time(ent)
                print(f"{i+1}) {pwd}")
                print(f"   Энтропия: {ent:.1f} бит, время взлома: ~ {years:.2e} лет")
            except ValueError as e:
                print(f"Ошибка: {e}")

def main():
    parser = argparse.ArgumentParser(description="Генератор паролей")
    parser.add_argument("-l", "--length", type=int, help="Длина пароля")
    parser.add_argument("--letters", action="store_true", help="Использовать буквы")
    parser.add_argument("--digits", action="store_true", help="Использовать цифры")
    parser.add_argument("--special", action="store_true", help="Использовать спецсимволы")
    parser.add_argument("--all", action="store_true", help="Использовать все типы символов")
    parser.add_argument("--exclude-similar", action="store_true", help="Исключить похожие")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Исключить двусмысленные")
    parser.add_argument("-c", "--count", type=int, default=1, help="Количество паролей")
    parser.add_argument("--interactive", action="store_true", help="Запустить интерактивный режим")
    args = parser.parse_args()

    pg = PasswordGenerator()
    if args.interactive or len(sys.argv) == 1:
        pg.run_interactive()
        return

    # Параметры
    length = args.length or pg.config['default_length']
    use_letters = args.all or args.letters or pg.config['use_letters']
    use_digits = args.all or args.digits or pg.config['use_digits']
    use_special = args.all or args.special or pg.config['use_special']
    exclude_similar = args.exclude_similar or pg.config['exclude_similar']
    exclude_ambiguous = args.exclude_ambiguous or pg.config['exclude_ambiguous']

    for i in range(args.count):
        try:
            pwd = pg.generate_password(length, use_letters, use_digits, use_special,
                                       exclude_similar, exclude_ambiguous)
            ent = pg.entropy(pwd)
            years = pg.crack_time(ent)
            print(f"{i+1}) {pwd}")
            if args.count == 1:
                print(f"Энтропия: {ent:.1f} бит, время взлома: ~ {years:.2e} лет")
        except ValueError as e:
            print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()
