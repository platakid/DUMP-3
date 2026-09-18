"""Choose an installed iPhone simulator without hard-coding an Xcode device name."""
import json
import re
import sys


def select_device(payload):
    candidates = []
    for runtime, devices in payload.get("devices", {}).items():
        match = re.search(r"\.iOS-(\d+)-(\d+)(?:-(\d+))?$", runtime)
        if not match:
            continue
        version = tuple(int(part or 0) for part in match.groups())
        if version < (17, 0, 0):
            continue
        for device in devices:
            if device.get("isAvailable") and device.get("name", "").startswith("iPhone"):
                candidates.append((version, device.get("state") == "Booted", device["udid"]))
    if not candidates:
        raise ValueError("No available iPhone simulator with iOS 17 or later is installed.")
    return max(candidates)[2]


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as file:
        payload = json.load(file)
    try:
        print(select_device(payload))
    except ValueError as error:
        sys.exit(str(error))
