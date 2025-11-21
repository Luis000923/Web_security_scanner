from colorama import Fore, Style
from utils.i18n import i18n

def print_banner():
    width = 76
    
    title = i18n.get('banner.title')
    subtitle = i18n.get('banner.subtitle')
    feat1 = "• " + i18n.get('banner.feature1')
    feat2 = "• " + i18n.get('banner.feature2')
    feat3 = "• " + i18n.get('banner.feature3')
    footer = i18n.get('banner.footer')

    def center(text, w, color=Fore.CYAN):
        padding = w - len(text)
        left = padding // 2
        right = padding - left
        return f"{Fore.CYAN}║{' ' * left}{color}{text}{Fore.CYAN}{' ' * right}║"

    def left_align(text, w, indent=3, color=Fore.WHITE):
        padding = w - len(text) - indent
        if padding < 0: padding = 0
        return f"{Fore.CYAN}║{' ' * indent}{color}{text}{Fore.CYAN}{' ' * padding}║"

    banner = (
        f"{Fore.CYAN}╔{'═' * width}╗\n"
        f"{center(title, width, Fore.GREEN)}\n"
        f"{center(subtitle, width, Fore.YELLOW)}\n"
        f"{left_align(feat1, width)}\n"
        f"{left_align(feat2, width)}\n"
        f"{left_align(feat3, width)}\n"
        f"{Fore.CYAN}║{' ' * width}║\n"
        f"{center(footer, width, Fore.RED)}\n"
        f"{Fore.CYAN}╚{'═' * width}╝\n"
        f"{Style.RESET_ALL}"
    )
    print(banner)
