"""
Authorization gate for tools that actively probe other systems.

SECURITY / LEGAL IDEA: Scanning or testing systems you do not own or have written
permission to test can be illegal (e.g. the US CFAA, UK Computer Misuse Act). Real
penetration tests start with a signed scope / rules-of-engagement document. These
helpers force you to pause and confirm authorization before any active probing.
"""
from __future__ import annotations

import sys

BANNER = """\
+--------------------------------------------------------------+
|  AUTHORIZED USE ONLY                                         |
|  Only test systems you OWN or have EXPLICIT PERMISSION to    |
|  test. Unauthorized scanning may be illegal.                 |
+--------------------------------------------------------------+"""


def require_authorization(target: str, assume_yes: bool = False) -> None:
    """Exit unless the user confirms they are authorized to test `target`."""
    print(BANNER)
    if assume_yes:
        print(f"[!] --i-have-permission supplied: proceeding against {target}\n")
        return
    if not sys.stdin.isatty():
        sys.exit("Refusing to run non-interactively without --i-have-permission.")
    answer = input(f"Do you own or have written permission to test '{target}'? [type 'yes']: ")
    if answer.strip().lower() != "yes":
        sys.exit("Authorization not confirmed. Exiting.")
    print()


def add_permission_flag(parser) -> None:
    """Add the standard --i-have-permission flag to an argparse parser."""
    parser.add_argument(
        "--i-have-permission",
        action="store_true",
        help="skip the interactive prompt; confirms you are authorized to test the target",
    )
