"""Live statistics box shown in the console"""

from nodpi.statistics import Statistics
from nodpi.ui.formatting import format_size, format_speed, visible_length

COL_WIDTH = 30
TITLE = "STATISTICS"


def render_stats(stats: Statistics) -> str:
    """Get formatted statistics display"""

    col_width = COL_WIDTH

    conns_stat = (
        f"\033[97mTotal: \033[93m{stats.total_connections}\033[0m".ljust(col_width)
        + "\033[97m| "
        + f"\033[97mMiss: \033[96m{stats.allowed_connections}\033[0m".ljust(col_width)
        + "\033[97m| "
        + f"\033[97mUnblock: \033[92m{stats.blocked_connections}\033[0m".ljust(col_width)
        + f"\033[97m| \033[97mErrors: \033[91m{stats.errors_connections}\033[0m".ljust(col_width)
    )

    traffic_stat = (
        f"\033[97mTotal: \033[96m{format_size(stats.traffic_out + stats.traffic_in)}\033[0m".ljust(
            col_width
        )
        + "\033[97m| "
        + f"\033[97mDL: \033[96m{format_size(stats.traffic_in)}\033[0m".ljust(col_width)
        + "\033[97m| "
        + f"\033[97mUL: \033[96m{format_size(stats.traffic_out)}\033[0m".ljust(col_width)
        + "\033[97m| "
    )

    speed_stat = (
        f"\033[97mDL: \033[96m{format_speed(stats.speed_in)}\033[0m".ljust(col_width)
        + "\033[97m| "
        + f"\033[97mUL: \033[96m{format_speed(stats.speed_out)}\033[0m".ljust(col_width)
        + "\033[97m| "
        + f"\033[97mAVG DL: \033[96m{format_speed(stats.average_in)}\033[0m".ljust(col_width)
        + "\033[97m| "
        + f"\033[97mAVG UL: \033[96m{format_speed(stats.average_out)}\033[0m".ljust(col_width)
    )

    inner_width = 35 + 1 + len(TITLE) + 1 + 35
    total_width = inner_width + 2

    top_border = f"\033[92m╭{'─' * 35} {TITLE} {'─' * 35}╮\033[0m"
    bottom_border = f"\033[92m╰{'─' * (inner_width)}╯\033[0m"

    lines = [
        f"\033[92m│  {'Conns'.ljust(8)}:\033[0m {conns_stat}",
        f"\033[92m│  {'Traffic'.ljust(8)}:\033[0m {traffic_stat}",
        f"\033[92m│  {'Speed'.ljust(8)}:\033[0m {speed_stat}",
    ]

    formatted_lines = []
    for line in lines:
        padding = total_width - visible_length(line) - 1
        formatted_lines.append(line + " " * padding + "\033[92m│\033[0m")

    return f"{top_border}\n" + "\n".join(formatted_lines) + f"\n{bottom_border}"
