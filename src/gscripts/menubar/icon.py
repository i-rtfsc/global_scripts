"""
Menu Bar Icon

Provides the icon for the menu bar application.
For macOS menu bar apps, we use a simple text-based icon.
"""

# Global Scripts icon - using text for now
# TODO: Replace with actual icon file in the future
MENUBAR_ICON = "GS"

# Alternative icons (can be configured)
ALTERNATIVE_ICONS = {
    "text": "GS",       # Text-based (current)
    "lightning": "⚡",  # Speed, automation
    "diamond": "◆",    # Premium, quality
    "circle": "●",     # Simple, minimal
    "star": "★",       # Excellence
    "gear": "⚙",       # System, tools
}


def get_icon(icon_name: str = "text") -> str:
    """
    Get menu bar icon by name

    Args:
        icon_name: Icon name from ALTERNATIVE_ICONS

    Returns:
        Icon character
    """
    return ALTERNATIVE_ICONS.get(icon_name, MENUBAR_ICON)
