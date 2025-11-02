#!/usr/bin/env python
"""
 Copyright (C) 2023  RedNaga. https://rednaga.io
 All rights reserved. Contact: rednaga@protonmail.com


 This file is part of APKiD


 Commercial License Usage
 ------------------------
 Licensees holding valid commercial APKiD licenses may use this file
 in accordance with the commercial license agreement provided with the
 Software or, alternatively, in accordance with the terms contained in
 a written agreement between you and RedNaga.


 GNU General Public License Usage
 --------------------------------
 Alternatively, this file may be used under the terms of the GNU General
 Public License version 3.0 as published by the Free Software Foundation
 and appearing in the file LICENSE.GPL included in the packaging of this
 file. Please visit http://www.gnu.org/copyleft/gpl.html and review the
 information to ensure the GNU General Public License version 3.0
 requirements will be met.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request
from codecs import open
from typing import Dict, Set

from apkid.output import colorize_tag
from apkid.rules import RulesManager

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def gen_rule():
    """Generate YARA rules from Exodus API."""

    def get_rule_path(file_type):
        return os.path.join(SCRIPT_DIR, "apkid", "rules", file_type, "trackers.yara")

    url = "https://reports.exodus-privacy.eu.org/api/trackers"
    try:
        with urllib.request.urlopen(url) as response:
            data_bytes = response.read()
            data = json.loads(data_bytes)
    except urllib.error.URLError:
        print(f"Error connecting to {url}. Skipping rule generation.", file=sys.stderr)
        return

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
        author      = "Abhi & Exodus API"
        url         = "{info.get("website")}"

    strings:
""",
            "apk": f"""
rule {rule_name} : tracker
{{
    meta:
        description = "{info.get("name").replace("Google", "G.").replace("Facebook", "FB.").replace("Notifications", "Notifs")}"
        author      = "Abhi & Exodus API"
        url         = "{info.get("website")}"

    strings:
""",
            "elf": f"""
rule {rule_name} : tracker
{{
    meta:
        description = "{info.get("name").replace("Google", "G.").replace("Facebook", "FB.").replace("Notifications", "Notifs")}"
        author      = "Abhi & Exodus API"
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
            rule_path = get_rule_path(file_type)
            existing_rules = ""
            if not os.path.exists(rule_path):
                with open(rule_path, "w") as f:
                    f.write('include "common.yara"\n')
            if os.path.exists(rule_path):
                with open(rule_path, "r") as f:
                    existing_rules = f.read()
            if rule_name not in existing_rules:
                with open(rule_path, "a") as f:
                    f.write(yara_rule)
            else:
                print(f"\rDuplicate rule name found: {rule_name}. Skipping.", end="")


def convert_readme():
    print("[*] Converting Markdown README to reStructuredText")
    import pypandoc

    readme_md_path = os.path.join(SCRIPT_DIR, "README.md")
    readme_rst_path = os.path.join(SCRIPT_DIR, "README.rst")

    rst = pypandoc.convert_file(readme_md_path, "rst")
    with open(readme_rst_path, "w+", encoding="utf-8") as f:
        f.write(rst)
    print(f"[*] Finished converting to README.rst ({len(rst)} bytes)")


if __name__ == "__main__":
    print("[*] Updating trackers rules")
    gen_rule()
    print()
    print("[*] Compiling Yara files without trackers")
    rules_manager = RulesManager(include_trackers=False)
    rules = rules_manager.compile()
    rules_count = rules_manager.save()
    print(f"[*] Saved {rules_count} rules to {rules_manager.rules_path}")
    print(f"[*] Rules hash: {rules_manager.hash}")

    print()
    print("[*] Compiling Yara files with trackers")
    rules_manager = RulesManager(include_trackers=True)
    rulest = rules_manager.compile()
    rules_count = rules_manager.save()
    print(f"[*] Saved {rules_count} rules to {rules_manager.rules_path}")
    print(f"[*] Rules hash: {rules_manager.hash}")

    tag_to_identifiers: Dict[str, Set[str]] = {}
    for rule in list(rules) + list(rulest):
        for t in rule.tags:
            if t not in tag_to_identifiers:
                tag_to_identifiers[t] = set()
            tag_to_identifiers[t].add(rule.identifier)
    tag_counts = dict([(k, len(v)) for k, v in tag_to_identifiers.items()])
    print("[*] Rule tag counts:")
    for tag in sorted(tag_counts.keys()):
        count = tag_counts[tag]
        if sys.stdout.isatty():
            print(f" |-> {colorize_tag(tag)}: {count}")
        else:
            print(f" |-> {tag}: {count}")

    if len(sys.argv) > 1:
        if sys.argv[1] == "register":
            print("[*] Registering ...")
            os.system("python setup.py register")
        if sys.argv[1] == "readme":
            convert_readme()

    print("[*] Finished preparing APKiD for release.")
