"""
console.py
Colorful terminal output helpers, built on 'rich'.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from severity import SEVERITY_COLOR, SEVERITY_ICON

console = Console()


def print_banner():
    banner = r"""
 ____  ____  ____     __    __              ____                    __
/ ___)/ ___)(  __)   / _\  (  )    ___  ____/_/  ___  ___  ___  ___  ____
\___ \\___ \ ) _)   /    \  )(    (___)(  __) (  __/(  ,\ (  __)/  ) (  __)
(____/(____/(____)  \_/\_/ (__)         \___)  \___) \___/ \___)\_/\ \___)

   SOC Threat Detection & Log Analyzer
"""
    console.print(Panel(Text(banner, style="bold cyan"), border_style="cyan"))


def print_summary(total_events, failed_count, brute_force_count, multi_ip_count):
    table = Table(title="Analysis Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Total Events", str(total_events))
    table.add_row("Failed Logins", str(failed_count))
    table.add_row("Brute Force Findings", str(brute_force_count))
    table.add_row("Multiple-IP Findings", str(multi_ip_count))
    console.print(table)


def print_alerts(alerts):
    if not alerts:
        console.print("[bold green]✔ No alerts triggered. Environment looks clean.[/bold green]")
        return

    table = Table(title="🚨 Alerts", show_header=True, header_style="bold red")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Detail")
    table.add_column("MITRE ATT&CK")

    for a in alerts:
        icon = SEVERITY_ICON.get(a["severity"], "")
        color = SEVERITY_COLOR.get(a["severity"], "white")
        table.add_row(
            f"[{color}]{icon} {a['severity']}[/{color}]",
            a["title"],
            a["detail"],
            a["mitre"],
        )
    console.print(table)


def print_event_counts(event_id_counts):
    table = Table(title="Event ID Counts", show_header=True, header_style="bold blue")
    table.add_column("Event ID")
    table.add_column("Count", justify="right")
    for eid, count in event_id_counts.most_common():
        table.add_row(str(eid), str(count))
    console.print(table)


def print_sigma_results(results):
    if not results:
        console.print("[dim]No Sigma rule matches.[/dim]")
        return
    table = Table(title="Sigma Rule Matches", show_header=True, header_style="bold yellow")
    table.add_column("Rule")
    table.add_column("Level")
    table.add_column("Match Count", justify="right")
    for title, info in results.items():
        table.add_row(title, info["level"], str(len(info["matches"])))
    console.print(table)


def print_status(message, style="cyan"):
    console.print(f"[{style}]{message}[/{style}]")
