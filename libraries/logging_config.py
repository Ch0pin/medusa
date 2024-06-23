import logging
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)  

class LoggerConsoleOutputFormat(logging.Formatter):
    COLORS = {
        logging.INFO: Fore.GREEN,       # Green color for INFO
        logging.WARNING: Fore.YELLOW,   # Yellow color for WARNING
        logging.ERROR: Fore.RED,        # Red color for ERROR
        logging.CRITICAL: Fore.RED + Style.BRIGHT  # Bright red color for CRITICAL
    }

    def format(self, record):
        log_level = record.levelno
        color_prefix = self.COLORS.get(log_level, '')
        color_suffix = Style.RESET_ALL
        
        formatted_time_level = f"{color_prefix}[{self.formatTime(record)} - {record.levelname}] - {color_suffix}"
        return f"{formatted_time_level} {record.getMessage()}"

    def formatTime(self, record, datefmt=None):
        """
        Override formatTime to customize the time formatting if needed.
        """
        if datefmt:
            s = logging.Formatter.formatTime(self, record, datefmt)
        else:
            s = logging.Formatter.formatTime(self, record, self.datefmt)
        return s

def setup_logging():
    formatter = LoggerConsoleOutputFormat()
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
