"""Original Medusa artwork shared by unified and legacy startup paths."""
import random

import click

_LOGO = '\n    ███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗ \n    ████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗    \n    ██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║\n    ██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║\n    ██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║\n    ╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ (Android) Version: dev  \n                                    \n 🪼 Type help for options 🪼 \n\n\n'


def render_logo(platform=None):
    labels = {'android': 'Android', 'ios': 'iOS', None: 'Android / iOS'}
    return _LOGO.replace('(Android)', f'({labels[platform]})')


def print_logo(platform=None):
    color = tuple(random.randint(0, 255) for _ in range(3))
    click.secho(render_logo(platform), fg=color, bold=True)
