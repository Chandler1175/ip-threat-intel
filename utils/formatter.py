def format_markdown(ip, results):
    md = f"# Threat Intelligence Report for {ip}\n\n"

    for r in results:
        source = r.get("source", "Unknown")

        md += f"## {source}\n"
        md += "| Field | Value |\n|------|------|\n"

        for key, value in r.items():
            if key == "source":
                continue

            if isinstance(value, list):
                value = ", ".join(value) if value else "None"

            md += f"| {key} | {value} |\n"

        md += "\n"

    return md
