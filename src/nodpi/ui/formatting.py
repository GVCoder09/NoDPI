"""Human readable formatting helpers for console output"""


def format_size(size: int) -> str:
    """Convert size to human readable format"""

    units = ["B", "KB", "MB", "GB"]
    unit = 0
    size_float = float(size)
    while size_float >= 1024 and unit < len(units) - 1:
        size_float /= 1024
        unit += 1
    return f"{size_float:.1f} {units[unit]}"


def format_speed(speed_bps: float) -> str:
    """Convert speed to human readable format"""

    if speed_bps <= 0:
        return "0 b/s"

    units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
    unit = 0
    speed = speed_bps
    while speed >= 1000 and unit < len(units) - 1:
        speed /= 1000
        unit += 1
    return f"{speed:.0f} {units[unit]}"


def visible_length(s: str) -> int:
    """Length of a string without ANSI escape sequences"""

    length = 0
    i = 0
    while i < len(s):
        if s[i] == "\x1b":
            i += 1
            while i < len(s) and s[i] != "m":
                i += 1
            i += 1
        else:
            length += 1
            i += 1
    return length
