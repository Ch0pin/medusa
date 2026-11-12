"""Original terminal device-picker presentation."""
from libraries.core.devices import DeviceSelectionError, detect_platform as detect_platform

def select_device(frida_api, device_id=None, host=None, input_fn=None, output=print, announce=None):
    if host:
        return frida_api.get_device_manager().add_remote_device(host)
    if device_id:
        return frida_api.get_device(device_id, timeout=5)
    devices = list(frida_api.enumerate_devices())
    if not devices:
        raise DeviceSelectionError("No mobile devices found. Connect a device or specify --host.")
    if announce is None:
        output('Available devices:\n')
    else:
        announce()
    for index, device in enumerate(devices):
        output(f"{index}) {device}")
    read = input if input_fn is None else input_fn
    while True:
        try:
            index = int(read('\nEnter the index of the device to use: '))
        except ValueError:
            continue
        except EOFError as exc:
            raise DeviceSelectionError('Device selection cancelled.') from exc
        if 0 <= index < len(devices):
            return devices[index]
