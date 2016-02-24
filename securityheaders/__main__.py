# -*- coding: utf-8 -*-

"""
    CLI Application to get security headers
    from a given URL.
"""


import click
import json
import textwrap
from prettytable import PrettyTable

from .core import analyze_url


def wrap(text):
    """Wraps the given text into multiple lines."""
    return "\n".join(textwrap.wrap(text, 50))


@click.command()
@click.version_option()
@click.argument("url", required=True)
@click.option("--json", "to_json", flag_value=True, help="Print the Security Headers analysis as JSON")
def cli(url, to_json):
    """Get Security Headers from a given URL.
    The data is fetched from SecurityHeaders.io.
    """
    if not to_json:
        click.echo("==> Analyzing Security Headers of {0}".format(click.style(url, bold=True)))

    # analyze security headers of given URL
    data = analyze_url(url)

    if to_json:
        click.echo(json.dumps(data, indent=4, sort_keys=True))
    else:
        click.echo("➤ Site: {0}".format(click.style(data["site"], bold=True)))
        click.echo("➤ IP Address: {0}".format(click.style(data["ip"], bold=True)))
        click.echo(click.style("➤ Security Headers:", bold=True))

        table = PrettyTable(["Header", "Value", "Rating", "Description"])
        table.align["Header"] = "l"
        table.align["Value"] = "l"
        table.align["Description"] = "l"

        header_styles = {
            "info": ("white", False),
            "good": ("green", True),
            "bad": ("red", True)
        }

        for header, info in data["headers"].items():
            fg_color, bold = header_styles[info["rating"]]
            header_text = click.style(header, bold=bold, fg=fg_color)
            value = info.get("value", "---")
            description = info.get("description", "---")
            table.add_row([header_text, wrap(value), info["rating"], wrap(description)])

        click.echo(table)


if __name__ == "__main__":
    cli()
