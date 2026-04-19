"""
Color Theme System for Cyber Defense System
Implements the Forest color palette with #002623 as dominant color
"""

class ColorTheme:
    """Forest color theme for cyber defense system"""
    
    # Primary Colors
    PRIMARY = "#002623"          # Forest dominant color (C87% M59% Y68% K71%)
    SECONDARY = "#054239"        # Forest secondary (C76% M32% Y54% K10%)
    
    # Forest Greens
    FOREST_LIGHT = "#b9a779"     # Golden Wheat (C6% M9% Y19% K0%)
    FOREST_MEDIUM = "#988561"     # Medium forest (C20% M29% Y52% K7%)
    FOREST_DARK = "#6b1f2a"       # Deep Umber (C39% M46% Y67% K20%)
    
    # Accent Colors
    ACCENT_RED = "#4a151e"        # Deep red (C44% M86% Y68% K65%)
    ACCENT_DARK = "#260f14"       # Dark red (C60% M75% Y64% K79%)
    
    # Neutral Colors
    WHITE = "#ffffff"             # Pure white
    LIGHT_GRAY = "#3d3a3b"       # Charcoal light (C67% M53% Y60% K50%)
    DARK_GRAY = "#161616"         # Charcoal dark (C73% M67% Y65% K80%)
    
    # Status Colors (adapted to forest theme)
    SUCCESS = "#988561"           # Forest medium for success
    WARNING = "#b9a779"           # Golden wheat for warnings
    ERROR = "#6b1f2a"             # Deep umber for errors
    INFO = "#054239"              # Forest secondary for info
    CRITICAL = "#4a151e"          # Deep red for critical
    
    # Progress Bar Colors
    PROGRESS_COMPLETE = "#988561"  # Forest medium
    PROGRESS_IN_PROGRESS = "#b9a779" # Golden wheat
    PROGRESS_WARNING = "#6b1f2a"   # Deep umber
    PROGRESS_CRITICAL = "#4a151e"   # Deep red
    
    # Chart Colors
    CHART_COLORS = [
        "#002623",  # Primary forest
        "#054239",  # Secondary forest
        "#b9a779",  # Golden wheat
        "#988561",  # Forest medium
        "#6b1f2a",  # Deep umber
        "#4a151e",  # Deep red
        "#3d3a3b",  # Charcoal light
        "#161616",  # Charcoal dark
    ]
    
    # Terminal/ASCII Colors
    class Terminal:
        """Terminal color codes for forest theme"""
        
        # ANSI color codes
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        
        # Forest theme colors (using standard ANSI codes approximated)
        PRIMARY = "\033[38;2;0;38;35m"      # Dark forest green
        SECONDARY = "\033[38;2;5;66;57m"    # Medium forest green
        LIGHT = "\033[38;2;185;167;121m"    # Golden wheat
        MEDIUM = "\033[38;2;152;133;97m"    # Forest medium
        DARK = "\033[38;2;107;31;42m"        # Deep umber
        ACCENT = "\033[38;2;74;21;30m"       # Deep red
        GRAY = "\033[38;2;61;58;59m"         # Charcoal
        WHITE = "\033[38;2;255;255;255m"     # White
        
        # Background colors
        BG_PRIMARY = "\033[48;2;0;38;35m"     # Dark forest green background
        BG_SECONDARY = "\033[48;2;5;66;57m"   # Medium forest background
        
        # Status colors
        SUCCESS = "\033[38;2;152;133;97m"     # Forest medium
        WARNING = "\033[38;2;185;167;121m"    # Golden wheat
        ERROR = "\033[38;2;107;31;42m"        # Deep umber
        INFO = "\033[38;2;5;66;57m"           # Medium forest
        CRITICAL = "\033[38;2;74;21;30m"       # Deep red
        
        # Combinations
        PRIMARY_BOLD = BOLD + PRIMARY
        SECONDARY_BOLD = BOLD + SECONDARY
        SUCCESS_BOLD = BOLD + SUCCESS
        WARNING_BOLD = BOLD + WARNING
        ERROR_BOLD = BOLD + ERROR
        CRITICAL_BOLD = BOLD + CRITICAL

class ColorUtils:
    """Utility functions for color theme management"""
    
    @staticmethod
    def get_color_for_value(value, max_value, color_type="progress"):
        """Get appropriate color based on value percentage"""
        percentage = (value / max_value) * 100 if max_value > 0 else 0
        
        if color_type == "progress":
            if percentage >= 90:
                return ColorTheme.PROGRESS_COMPLETE
            elif percentage >= 70:
                return ColorTheme.PROGRESS_IN_PROGRESS
            elif percentage >= 40:
                return ColorTheme.PROGRESS_WARNING
            else:
                return ColorTheme.PROGRESS_CRITICAL
        
        elif color_type == "status":
            if percentage >= 80:
                return ColorTheme.SUCCESS
            elif percentage >= 60:
                return ColorTheme.WARNING
            elif percentage >= 40:
                return ColorTheme.ERROR
            else:
                return ColorTheme.CRITICAL
        
        return ColorTheme.PRIMARY
    
    @staticmethod
    def get_terminal_color_for_value(value, max_value, color_type="progress"):
        """Get terminal color based on value percentage"""
        percentage = (value / max_value) * 100 if max_value > 0 else 0
        
        if color_type == "progress":
            if percentage >= 90:
                return ColorTheme.Terminal.SUCCESS
            elif percentage >= 70:
                return ColorTheme.Terminal.WARNING
            elif percentage >= 40:
                return ColorTheme.Terminal.ERROR
            else:
                return ColorTheme.Terminal.CRITICAL
        
        elif color_type == "status":
            if percentage >= 80:
                return ColorTheme.Terminal.SUCCESS
            elif percentage >= 60:
                return ColorTheme.Terminal.WARNING
            elif percentage >= 40:
                return ColorTheme.Terminal.ERROR
            else:
                return ColorTheme.Terminal.CRITICAL
        
        return ColorTheme.Terminal.PRIMARY

# Global theme instance
theme = ColorTheme()
color_utils = ColorUtils()

# Export main components
__all__ = ["ColorTheme", "ColorUtils", "theme", "color_utils"]
