"""
This script generates a benign test file that contains the specific patterns checked for by find_brickstorm.sh.
"""


def build_test_file(path: str = "brickstorm_testfile.elf") -> None:
    """
    Build a benign test file containing the required patterns.

    Args:
        path (str): The path where the test file will be created.
    """
    # Generate Minimal ELF header (64-bit)
    elf_header = b'\x7fELF' + b'\x02\x01\x01' + b'\x00' * 9 + b'\x00' * (64 - 16)

    # Set required/expected strings
    required_strings = [
        b'regex',
        b'mime',
        b'decompress',
        b'MIMEHeader',
        b'ResolveReference',
        b'115792089210356248762697446949407573529996955224135760342422259061068512044369'
        b'115792089210356248762697446949407573530086143415290314195533631308867097853951',
    ]

    # Generate hex pattern that matches this regex:
    # 488b05........48890424e8........48b8................48890424(..){0,5}e8........eb..
    hex_pattern = (
        b'\x48\x8b\x05\x01\x02\x03\x04'          # 48 8B 05 ?? ?? ?? ??
        b'\x48\x89\x04\x24'                      # 48 89 04 24
        b'\xe8\x05\x06\x07\x08'                  # E8 ?? ?? ?? ??
        b'\x48\xb8\x11\x22\x33\x44\x55\x66\x77\x88'  # 48 B8 ?? x8
        b'\x48\x89\x04\x24'                      # 48 89 04 24
        b'\x90' * 3 +                             # (..){0,5} → use 3 bytes
        b'\xe8\x09\x0A\x0B\x0C'                  # E8 ?? ?? ?? ??
        b'\xeb\xff'                              # EB ??
    )

    # Combine ELF header, strings, then pattern
    content = elf_header + b'\n'.join(required_strings) + b'\n' + hex_pattern

    with open(path, "wb") as f:
        f.write(content)

    print(f"[+] Test file created: {path}")


if __name__ == "__main__":
    build_test_file()
