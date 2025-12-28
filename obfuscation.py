import random
import string

GREEN = "\033[92m"
RED = "\033[91m"
WHITE = "\033[97m"
RESET = "\033[0m"

input_file = "loader.cpp"
output_file = "loader-obfs.cpp"

INSERT_LINES = [14, 22]
CHAR_MIN_LEN = 20
CHAR_MAX_LEN = 50
MIN_VARS = 3000
MAX_VARS = 7000

ascii_art = r"""
▒█████   ▄▄▄▄     █████▒ ██████
▒██▒  ██▒▓█████▄ ▓██   ▒▒██    ▒
▒██░  ██▒▒██▒ ▄██▒████ ░░ ▓██▄
▒██   ██░▒██░█▀  ░▓█▒  ░  ▒   ██▒
░ ████▓▒░░▓█  ▀█▓░▒█░   ▒██████▒▒
░ ▒░▒░▒░ ░▒▓███▀▒ ▒ ░   ▒ ▒▓▒ ▒ ░
  ░ ▒ ▒░ ▒░▒   ░  ░     ░ ░▒  ░ ░
░ ░ ░ ▒   ░    ░  ░ ░   ░  ░  ░
    ░ ░   ░                   ░
               ░   https://github.com/X-croot
"""

print(f"{RED}{ascii_art}{RESET}")

def random_identifier(used_names, length=10):
    while True:
        name = ''.join(random.choices(string.ascii_lowercase, k=length))
        if name not in used_names:
            used_names.add(name)
            return name

def random_char_array(used_names):
    length = random.randint(CHAR_MIN_LEN, CHAR_MAX_LEN)
    content = ''.join(random.choices(string.ascii_letters + string.digits + "_", k=length))
    var_name = random_identifier(used_names)
    return f'char {var_name}[] = "{content}";'

def insert_random_variables(lines, insert_line, used_names):
    insert_index = insert_line - 1
    count = random.randint(MIN_VARS, MAX_VARS)
    log_ok(f"Inserting {count} random variables at line {insert_line} ...")
    new_vars = [random_char_array(used_names) for _ in range(count)]
    for var in reversed(new_vars):
        lines.insert(insert_index, var + "\n")
    return count

def log_ok(message):
    print(f"{GREEN}[+]{RESET} {WHITE}{message}{RESET}")

def log_err(message):
    print(f"{RED}[-]{RESET} {WHITE}{message}{RESET}")

def main():
    used_names = set()
    log_ok("Reading loader.cpp")
    with open(input_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    total_inserted = 0
    for insert_line in sorted(INSERT_LINES, reverse=True):
        total_inserted += insert_random_variables(lines, insert_line, used_names)

    log_ok("Writing new file -> loader-obfs.cpp")
    with open(output_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    log_ok(f"Done! Inserted a total of {total_inserted} unique char[] variables.")
    log_ok(f"Output file: {output_file}")

if __name__ == "__main__":
    try:
        main()
        log_ok("All operations completed successfully.")
    except Exception as e:
        log_err(f"Error: {e}")
