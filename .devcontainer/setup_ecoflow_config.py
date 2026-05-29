#!/usr/bin/env python3
"""
EcoFlow Cloud Auto-Configuration Script

This script pre-populates the Home Assistant config entries for the EcoFlow Cloud
integration, allowing automatic setup on container restart.

Supports two authentication modes:

  Public API (access key + secret key):
    - ECOFLOW_ACCESS_KEY: Your EcoFlow Public API access key
    - ECOFLOW_SECRET_KEY: Your EcoFlow Public API secret key
    - ECOFLOW_API_HOST: API host (default: api-e.ecoflow.com)
    - ECOFLOW_DEVICES: JSON array of devices, e.g.:
      [{"sn": "DEVICE_SN", "name": "My Device", "type": "Stream AC"}]

  Private API (email + password):
    - ECOFLOW_USERNAME: Your EcoFlow account email
    - ECOFLOW_PASSWORD: Your EcoFlow account password
    - ECOFLOW_API_HOST: API host (default: api.ecoflow.com for private API)
    - ECOFLOW_DEVICES: JSON array of devices (same format as above)
      Common private API device types: STREAM_AC, STREAM_PRO, STREAM_ULTRA,
      DELTA_PRO, DELTA_2, RIVER_2, etc.

    Then run: python3 setup_ecoflow_config.py
"""

import json
import os
import uuid
from pathlib import Path


# Configuration defaults
DEFAULT_PUBLIC_API_HOST = "api-e.ecoflow.com"
DEFAULT_PRIVATE_API_HOST = "api.ecoflow.com"
DEFAULT_GROUP = "Home"
CONFIG_VERSION = 11

# Default device options
DEFAULT_OPTIONS = {
    "refresh_period_sec": 5,
    "power_step": 100,
    "diagnostic_mode": False,
    "verbose_status_mode": False,
    "assume_offline_sec": 300,
}


def get_env_or_exit(name: str) -> str:
    """Get environment variable or exit with error."""
    value = os.environ.get(name)
    if not value:
        print(f"Error: Environment variable {name} is required but not set.")
        exit(1)
    return value


def parse_devices(devices_json: str) -> list[dict]:
    """Parse devices JSON string into list of device dicts."""
    try:
        devices = json.loads(devices_json)
        if not isinstance(devices, list):
            raise ValueError("ECOFLOW_DEVICES must be a JSON array")
        for device in devices:
            if not all(k in device for k in ("sn", "name", "type")):
                raise ValueError("Each device must have 'sn', 'name', and 'type' keys")
        return devices
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in ECOFLOW_DEVICES: {e}")
        exit(1)


def _build_devices_payload(devices: list[dict]) -> tuple[dict, dict]:
    """Build device_list_data and device_list_options dicts from device list."""
    device_list_data = {}
    device_list_options = {}
    for device in devices:
        sn = device["sn"]
        device_list_data[sn] = {
            "device_name": device["name"],
            "device_type": device["type"],
        }
        device_list_options[sn] = {
            "refresh_period_sec": device.get("refresh_period_sec", DEFAULT_OPTIONS["refresh_period_sec"]),
            "power_step": device.get("power_step", DEFAULT_OPTIONS["power_step"]),
            "diagnostic_mode": device.get("diagnostic_mode", DEFAULT_OPTIONS["diagnostic_mode"]),
            "verbose_status_mode": device.get("verbose_status_mode", DEFAULT_OPTIONS["verbose_status_mode"]),
            "assume_offline_sec": device.get("assume_offline_sec", DEFAULT_OPTIONS["assume_offline_sec"]),
        }
    return device_list_data, device_list_options


def create_public_api_config_entry(
    access_key: str,
    secret_key: str,
    api_host: str,
    devices: list[dict],
    group: str = DEFAULT_GROUP,
) -> dict:
    """Create a config entry using the EcoFlow Public API (access key + secret key)."""
    entry_id = str(uuid.uuid4()).replace("-", "")
    device_list_data, device_list_options = _build_devices_payload(devices)
    return {
        "entry_id": entry_id,
        "version": CONFIG_VERSION,
        "minor_version": 1,
        "domain": "ecoflow_cloud",
        "title": group,
        "data": {
            "group": group,
            "api_host": api_host,
            "access_key": access_key,
            "secret_key": secret_key,
            "devices_list": device_list_data,
        },
        "options": {
            "devices_list": device_list_options,
        },
        "pref_disable_new_entities": False,
        "pref_disable_polling": False,
        "source": "user",
        "unique_id": f"group-{group}",
        "disabled_by": None,
    }


def create_private_api_config_entry(
    username: str,
    password: str,
    api_host: str,
    devices: list[dict],
    group: str = DEFAULT_GROUP,
) -> dict:
    """Create a config entry using the EcoFlow Private API (email + password)."""
    entry_id = str(uuid.uuid4()).replace("-", "")
    device_list_data, device_list_options = _build_devices_payload(devices)
    return {
        "entry_id": entry_id,
        "version": CONFIG_VERSION,
        "minor_version": 1,
        "domain": "ecoflow_cloud",
        "title": group,
        "data": {
            "group": group,
            "api_host": api_host,
            "username": username,
            "password": password,
            "devices_list": device_list_data,
        },
        "options": {
            "devices_list": device_list_options,
        },
        "pref_disable_new_entities": False,
        "pref_disable_polling": False,
        "source": "user",
        "unique_id": f"group-{group}",
        "disabled_by": None,
    }


def load_existing_config(config_path: Path) -> dict:
    """Load existing config entries file or return empty structure."""
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"version": 1, "minor_version": 1, "key": "core.config_entries", "data": {"entries": []}}


def save_config(config_path: Path, config: dict) -> None:
    """Save config entries file."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Config saved to: {config_path}")


def main():
    group = os.environ.get("ECOFLOW_GROUP", DEFAULT_GROUP)
    config_dir = os.environ.get("HA_CONFIG_DIR", "/config")
    devices_json = os.environ.get("ECOFLOW_DEVICES")

    # Detect auth mode: private API takes priority if username/password present
    username = os.environ.get("ECOFLOW_USERNAME")
    password = os.environ.get("ECOFLOW_PASSWORD")
    access_key = os.environ.get("ECOFLOW_ACCESS_KEY")
    secret_key = os.environ.get("ECOFLOW_SECRET_KEY")

    if not (username and password) and not (access_key and secret_key):
        print("No credentials configured — skipping auto-configuration.")
        print("Configure the integration manually via the Home Assistant UI.")
        return

    if not devices_json:
        print("ECOFLOW_DEVICES not set — skipping auto-configuration.")
        print("Set ECOFLOW_DEVICES in .devcontainer/.env with your device SN, then restart.")
        return

    devices = parse_devices(devices_json)

    if username and password:
        api_host = os.environ.get("ECOFLOW_API_HOST", DEFAULT_PRIVATE_API_HOST)
        print(f"Using Private API (email/password) for {len(devices)} device(s)...")
        new_entry = create_private_api_config_entry(username, password, api_host, devices, group)
        auth_desc = f"username={username}"
    else:
        api_host = os.environ.get("ECOFLOW_API_HOST", DEFAULT_PUBLIC_API_HOST)
        print(f"Using Public API (access/secret key) for {len(devices)} device(s)...")
        new_entry = create_public_api_config_entry(access_key, secret_key, api_host, devices, group)
        auth_desc = f"access_key={access_key[:8]}..."

    # Path to Home Assistant config entries
    config_path = Path(config_dir) / ".storage" / "core.config_entries"

    config = load_existing_config(config_path)
    config["data"]["entries"] = [
        entry for entry in config["data"]["entries"]
        if entry.get("domain") != "ecoflow_cloud"
    ]
    config["data"]["entries"].append(new_entry)
    save_config(config_path, config)

    print("EcoFlow Cloud integration configured successfully!")
    print(f"  - API Host: {api_host}")
    print(f"  - Auth: {auth_desc}")
    print(f"  - Group: {group}")
    print(f"  - Devices: {', '.join(d['name'] + ' (' + d['sn'] + ')' for d in devices)}")


if __name__ == "__main__":
    main()
