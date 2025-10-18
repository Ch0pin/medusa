# android_flags.py
"""
Android Flag Decoder
Supports: Intent, PendingIntent, and ContentProvider / ContentResolver flags
"""

# Intent flags (Activity, Broadcast, etc.)
INTENT_FLAGS = {
    "FLAG_GRANT_READ_URI_PERMISSION": 0x00000001,
    "FLAG_GRANT_WRITE_URI_PERMISSION": 0x00000002,
    "FLAG_FROM_BACKGROUND": 0x00000004,
    "FLAG_DEBUG_LOG_RESOLUTION": 0x00000008,
    "FLAG_EXCLUDE_STOPPED_PACKAGES": 0x00000010,
    "FLAG_INCLUDE_STOPPED_PACKAGES": 0x00000020,
    "FLAG_GRANT_PERSISTABLE_URI_PERMISSION": 0x00000040,
    "FLAG_GRANT_PREFIX_URI_PERMISSION": 0x00000080,
    "FLAG_DIRECT_BOOT_AUTO": 0x00000100,
    "FLAG_IGNORE_EPHEMERAL": 0x00000200,
    "FLAG_ACTIVITY_NO_HISTORY": 0x40000000,
    "FLAG_ACTIVITY_SINGLE_TOP": 0x20000000,
    "FLAG_ACTIVITY_NEW_TASK": 0x10000000,
    "FLAG_ACTIVITY_MULTIPLE_TASK": 0x08000000,
    "FLAG_ACTIVITY_CLEAR_TOP": 0x04000000,
    "FLAG_ACTIVITY_FORWARD_RESULT": 0x02000000,
    "FLAG_ACTIVITY_PREVIOUS_IS_TOP": 0x01000000,
    "FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS": 0x00800000,
    "FLAG_ACTIVITY_BROUGHT_TO_FRONT": 0x00400000,
    "FLAG_ACTIVITY_RESET_TASK_IF_NEEDED": 0x00200000,
    "FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY": 0x00100000,
    "FLAG_ACTIVITY_NEW_DOCUMENT": 0x00080000,
    "FLAG_ACTIVITY_NO_USER_ACTION": 0x00040000,
    "FLAG_ACTIVITY_REORDER_TO_FRONT": 0x00020000,
    "FLAG_ACTIVITY_NO_ANIMATION": 0x00010000,
    "FLAG_ACTIVITY_CLEAR_TASK": 0x00008000,
    "FLAG_ACTIVITY_TASK_ON_HOME": 0x00004000,
    "FLAG_ACTIVITY_RETAIN_IN_RECENTS": 0x00002000,
    "FLAG_RECEIVER_REGISTERED_ONLY": 0x40000000,
    "FLAG_RECEIVER_REPLACE_PENDING": 0x20000000,
    "FLAG_RECEIVER_FOREGROUND": 0x10000000,
    "FLAG_RECEIVER_NO_ABORT": 0x08000000,
    "FLAG_RECEIVER_EXCLUDE_BACKGROUND": 0x00800000,
    "FLAG_RECEIVER_INCLUDE_BACKGROUND": 0x00400000,
    "FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS": 0x00200000,
}

# PendingIntent flags
PENDING_INTENT_FLAGS = {
    "FLAG_ONE_SHOT": 0x40000000,
    "FLAG_NO_CREATE": 0x20000000,
    "FLAG_CANCEL_CURRENT": 0x10000000,
    "FLAG_UPDATE_CURRENT": 0x08000000,
    "FLAG_IMMUTABLE": 0x04000000,
    "FLAG_MUTABLE": 0x02000000,
}

# Content Provider / Content Resolver / URI permission flags
CONTENT_FLAGS = {
    # Grant modes (same values used in Intent flags)
    "FLAG_GRANT_READ_URI_PERMISSION": 0x00000001,
    "FLAG_GRANT_WRITE_URI_PERMISSION": 0x00000002,
    "FLAG_GRANT_PERSISTABLE_URI_PERMISSION": 0x00000040,
    "FLAG_GRANT_PREFIX_URI_PERMISSION": 0x00000080,

    # Query or open flags
    "QUERY_SORT_DESCENDING": 0x00000001,
    "QUERY_SORT_ASCENDING": 0x00000002,

    # Content resolver options (added in Android 11+)
    "RESOLVER_USE_CREDENTIALS": 0x00000004,
    "RESOLVER_IGNORE_SECURITY": 0x00000008,

    # Context permission flags
    "CONTEXT_INCLUDE_CODE": 0x00000001,
    "CONTEXT_IGNORE_SECURITY": 0x00000002,
    "CONTEXT_RESTRICTED": 0x00000004,
}


def decode_flags(value: int, flags_dict: dict):
    """Return list of symbolic flag names matching a numeric value."""
    return [name for name, flag in flags_dict.items() if value & flag]


def describe_flags(value: int, flags_dict: dict, title: str = "Flags"):
    """Pretty-print which flags correspond to a numeric value."""
    print(f"\n{title}")
    print("=" * len(title))
    print(f"Value: {value} (0x{value:X})")
    matched = decode_flags(value, flags_dict)
    if matched:
        print("Matched flags:")
        for flag in matched:
            print(f"  • {flag}")
    else:
        print("  (No known flags matched)")
