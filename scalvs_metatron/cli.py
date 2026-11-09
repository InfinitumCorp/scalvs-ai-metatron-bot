"""Command line for the Metatron product settings and geo hook."""

from __future__ import annotations

import argparse
import json
import sys

from scalvs_metatron.geo_fetch import GeoFetchError
from scalvs_metatron.geo_hook import annotate, policy_decision
from scalvs_metatron.geo_loader import GeoDataError
from scalvs_metatron.settings import (
    SettingsError,
    describe_geo_routing,
    set_geo_routing,
)

_EPILOG = """
Geo routing is off by default. While it is off, cyber policy, annotation,
and logging stay on the default path and do not read geo datasets.

`settings --geo-routing on|off` persists the toggle. On annotate and policy,
`--geo-routing` and `--no-geo-routing` apply to the current process only.
INFINITUM_GEO_ENABLED, when set to on or off, overrides the saved toggle for
the current process. A process flag wins over the environment.
""".strip()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scalvs-metatron",
        description="Scalvs.ai Metatron bot product tools.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--config",
        help="Settings file. Defaults to the user config path.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    settings = commands.add_parser(
        "settings",
        parents=[shared],
        help="Show or persist the geo-routing toggle (default off).",
        description="Show or persist the geo-routing toggle. The saved default is off.",
    )
    settings.add_argument(
        "--geo-routing",
        choices=("on", "off"),
        help="Persist geo routing. Off keeps the default behavior.",
    )

    annotate_cmd = commands.add_parser(
        "annotate",
        parents=[shared],
        help="Annotate a record. Geo fields are added only when geo routing is on.",
    )
    _add_subject(annotate_cmd)
    _add_process_flag(annotate_cmd)

    policy = commands.add_parser(
        "policy",
        parents=[shared],
        help="Print the cyber policy decision. Off matches the default decision.",
    )
    _add_subject(policy)
    _add_process_flag(policy)
    return parser


def _add_subject(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ip", help="IP address to annotate when geo routing is on.")
    parser.add_argument("--domain", help="Domain to annotate when geo routing is on.")


def _add_process_flag(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--geo-routing",
        action="store_const",
        const=True,
        dest="geo_flag",
        help="Turn geo routing on for this process without saving it.",
    )
    group.add_argument(
        "--no-geo-routing",
        action="store_const",
        const=False,
        dest="geo_flag",
        help="Turn geo routing off for this process without saving it.",
    )
    parser.set_defaults(geo_flag=None)


def _print_toggle(state: dict) -> None:
    print(f"geo-routing: {'on' if state['geo_routing'] else 'off'}")
    print(f"effective: {'on' if state['effective'] else 'off'}")
    print(f"source: {state['source']}")
    print(f"config: {state['config']}")


def _emit(payload: dict) -> None:
    print(json.dumps(payload, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "settings":
            if args.geo_routing is not None:
                set_geo_routing(args.geo_routing == "on", args.config)
            _print_toggle(describe_geo_routing(config_path=args.config))
            return 0
        record = {}
        if args.ip is not None:
            record["ip"] = args.ip
        if args.domain is not None:
            record["domain"] = args.domain
        if args.command == "annotate":
            _emit(
                annotate(
                    record,
                    config_path=args.config,
                    flag=args.geo_flag,
                )
            )
            return 0
        _emit(
            policy_decision(
                record,
                config_path=args.config,
                flag=args.geo_flag,
            )
        )
        return 0
    except (SettingsError, GeoDataError, GeoFetchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
