"""Device selection without importing either platform's command implementation."""


class DeviceSelectionError(ValueError):
    pass


def detect_platform(device, override=None):
    """Use OS metadata, never USB/remote transport or a marketing device name."""
    try:
        params = device.query_system_parameters()
    except Exception as exc:
        if override:
            return override
        raise DeviceSelectionError(
            "Cannot read device OS metadata. Specify --platform android or ios."
        ) from exc
    os_info = params.get("os", {})
    os_id = os_info.get("id", "") if isinstance(os_info, dict) else os_info
    detected = {"android": "android", "ios": "ios", "ipados": "ios"}.get(str(os_id).lower())
    if detected and override and detected != override:
        raise DeviceSelectionError(f"Selected device is {detected}, but --platform is {override}.")
    if detected:
        return detected
    if override:
        return override
    raise DeviceSelectionError(
        f"Unsupported or unknown device OS {os_id!r}. Specify --platform only for a known Android/iOS device."
    )
