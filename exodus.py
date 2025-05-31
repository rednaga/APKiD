import os
import re

import requests


def gen_rule():
    """Generate YARA rules from Exodus API."""

    url = "https://reports.exodus-privacy.eu.org/api/trackers"
    response = requests.get(url)
    data = response.json()

    trackers = data.get("trackers")

    for _, info in trackers.items():
        code_signature = info.get("code_signature")
        network_signature = info.get("network_signature")
        if network_signature == "\\.facebook\\.com":
            network_signature = ""
        if info.get("name") == "Google Ads":
            network_signature = ""
            code_signature = "com.google.android.gms.ads.identifier"
        code_signature = code_signature.replace(".", "\\.").replace("/", r"\\")
        network_signature = network_signature.replace("/", r"\\")
        code_signature2 = code_signature.replace(".", "/")
        if not code_signature and not network_signature:
            continue
        rule_name = re.sub(
            r"[^a-zA-Z]", "_", info.get("name").strip().replace(" ", "_")
        ).replace("__", "_")
        if rule_name.endswith("_"):
            rule_name = rule_name[:-1]
        rule_name = rule_name.lower()

        yara_rules = {
            "dex": f"""
rule {rule_name} : tracker
{{
    meta:
        description = "{info.get("name").replace("Google", "G.").replace("Facebook", "FB.").replace("Notifications", "Notifs")}"
        author      = "Abhi"
        url         = "{info.get("website")}"

    strings:
""",
            "apk": f"""
rule {rule_name} : tracker
{{
    meta:
        description = "{info.get("name").replace("Google", "G.").replace("Facebook", "FB.").replace("Notifications", "Notifs")}"
        author      = "Abhi"
        url         = "{info.get("website")}"

    strings:
""",
            "elf": f"""
rule {rule_name} : tracker
{{
    meta:
        description = "{info.get("name").replace("Google", "G.").replace("Facebook", "FB.").replace("Notifications", "Notifs")}"
        author      = "Abhi"
        url         = "{info.get("website")}"

    strings:
""",
        }

        if code_signature:
            yara_rules["dex"] += f"        $code_signature    = /{code_signature}/"
            yara_rules["apk"] += f"        $code_signature    = /{code_signature}/"
            yara_rules["elf"] += f"        $code_signature    = /{code_signature}/"
        if network_signature:
            yara_rules["dex"] += f"\n        $network_signature = /{network_signature}/"
            yara_rules["apk"] += f"\n        $network_signature = /{network_signature}/"
            yara_rules["elf"] += f"\n        $network_signature = /{network_signature}/"
        if code_signature2:
            yara_rules["dex"] += f"\n        $code_signature2   = /{code_signature2}/"
            yara_rules["apk"] += f"\n        $code_signature2   = /{code_signature2}/"
            yara_rules["elf"] += f"\n        $code_signature2   = /{code_signature2}/"

        yara_rules["dex"] += """

    condition:
        is_dex and any of them
}
"""
        yara_rules["apk"] += """

    condition:
        is_apk and any of them
}
"""
        yara_rules["elf"] += """

    condition:
        is_elf and any of them
}
"""

        for file_type, yara_rule in yara_rules.items():
            existing_rules = ""
            if not os.path.exists(f"apkid/rules/{file_type}/trackers.yara"):
                with open(f"apkid/rules/{file_type}/trackers.yara", "w") as f:
                    f.write('include "common.yara"\n')
            if os.path.exists(f"apkid/rules/{file_type}/trackers.yara"):
                with open(f"apkid/rules/{file_type}/trackers.yara", "r") as f:
                    existing_rules = f.read()
            if rule_name not in existing_rules:
                with open(f"apkid/rules/{file_type}/trackers.yara", "a") as f:
                    f.write(yara_rule)
            else:
                print(f"\rDuplicate rule name found: {rule_name}. Skipping.", end="")


gen_rule()
print()
