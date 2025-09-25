#!/bin/sh

# Copyright 2025 Google LLC
# Copyright 2025 Jared Hendrickson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may- obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script attempts to replicate the YARA rule G_APT_Backdoor_BRICKSTORM_3
# on systems without YARA installed. This version is modified for pfSense/FreeBSD
# compatibility, using sh, hexdump, and standard grep.
#
# Usage: ./find_brickstorm.sh /path/to/file1 /path/to/directory/

# --- START: OS-specific `find` compatibility ---
if [ "$(uname -s)" = "Linux" ]; then
    FIND_OPTS="-L"
    REGEX_EXPR="-regextype posix-extended"
else
    # BSD/pfSense `find`
    FIND_OPTS="-LE"
    REGEX_EXPR=""
fi
# --- END: OS-specific `find` compatibility ---

# --- YARA Rule Definitions ---
# This long number is from the YARA rule's $str7
long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
# --- End of Definitions ---

# Function to dynamically create a UTF-16LE (wide) regex pattern
# Uses a portable octal escape (`\000`) for the null byte.
build_wide_pattern() {
    printf %s "$1" | sed 's/./&\\000/g'
}

# Function to check a single file (Definitive, high-compatibility version)
check_file() {
    local file="$1"

    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi

    # --- Condition 1: Check ELF Header ---
    file_header=$(hexdump -n 2 -v -e '1/1 "%02x"' "$file" 2>/dev/null)
    if [ "$file_header" != "7f45" ]; then
        return
    fi

    # --- Condition 2: Check for all strings ($str2 - $str7) ---
    str2="regex"
    str2_wide=$(build_wide_pattern "$str2")
    if ! grep -iaEq "$str2|$str2_wide" "$file"; then return; fi

    str3="mime"
    str3_wide=$(build_wide_pattern "$str3")
    if ! grep -iaEq "$str3|$str3_wide" "$file"; then return; fi

    str4="decompress"
    str4_wide=$(build_wide_pattern "$str4")
    if ! grep -iaEq "$str4|$str4_wide" "$file"; then return; fi

    str5="MIMEHeader"
    str5_wide=$(build_wide_pattern "$str5")
    if ! grep -iaEq "$str5|$str5_wide" "$file"; then return; fi

    str6="ResolveReference"
    str6_wide=$(build_wide_pattern "$str6")
    if ! grep -iaEq "$str6|$str6_wide" "$file"; then return; fi

    str7_wide=$(build_wide_pattern "$long_num")
    if ! grep -iaEq "$long_num|$str7_wide" "$file"; then return; fi

    # --- Condition 3: Check for hex string (Streaming Loop Method) ---
    match_found=0
    part1="488b05........48890424e8........48b8................48890424"
    part2="e8........eb.."

    i=0
    while [ $i -le 5 ]; do
        # Calculate gap length in hex characters (bytes * 2)
        gap_len=$((i * 2))
        # Create a string of `.` wildcards for the gap
        gap_wildcards=$(printf '%.*s' "$gap_len" '............') # 12 dots is more than enough

        pattern_to_check="${part1}${gap_wildcards}${part2}"

        # Stream the hexdump directly into a simple grep for each gap length
        if hexdump -v -e '1/1 "%02x"' "$file" | tr -d '[:space:]' | grep -Eq "$pattern_to_check"; then
            match_found=1
            break # Exit loop on first match
        fi
        i=$((i + 1))
    done

    # If no match was found after checking all gap lengths, return
    if [ $match_found -eq 0 ]; then
        return
    fi

    # --- All conditions met ---
    echo "MATCH: $file"
    echo "Found evidence of potential BRICKSTORM compromise."
    echo "You should consider performing a forensic investigation of the system."
    echo
}

# --- Main script execution ---

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <file_or_directory1> [file_or_directory2] ..."
    echo "Checks files for strings and byte sequences present in the BRICKSTORM backdoor."
    exit 1
fi

# Loop over all provided arguments
for target in "$@"; do
    if [ -d "$target" ]; then
        # Use a `find | while read` loop for compatibility.
        find $FIND_OPTS "$target" $REGEX_EXPR -type f -size -10M \
        \( -not -path "/proc/*" -and -not -regex ".*/tmp/[0-9]{10}/.*" -and -not -regex ".*/var/crash/nsproflog/newproflog.*" -and -not -regex ".*/var/log/notice.log" \) \
        -print 2>/dev/null | while IFS= read -r file_to_check; do
            # Ensure the read variable is not empty before processing
            if [ -n "$file_to_check" ]; then
                check_file "$file_to_check"
            fi
        done
    elif [ -f "$target" ]; then
        # If it's a file, check it directly
        check_file "$target"
    else
        echo "Warning: '$target' is not a valid file or directory. Skipping." >&2
    fi
done
