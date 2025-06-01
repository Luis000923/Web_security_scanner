from colorama import Fore, Style

def print_banner():
    banner = (
        f"{Fore.CYAN}╔════════════════════════════════════════════════════════════════════════════╗\n"
        f"{Fore.CYAN}║                      {Fore.GREEN} WEB SECURITY SCANNER v3.1 - 2025{Fore.CYAN}                     ║\n"
        f"{Fore.CYAN}║ {Fore.YELLOW}   Escáner avanzado de seguridad web para detección y análisis completos   {Fore.CYAN}║\n"
        f"{Fore.CYAN}║ {Fore.WHITE}   • Detecta vulnerabilidades                                              {Fore.CYAN}║\n"
        f"{Fore.CYAN}║ {Fore.WHITE}   • Identifica tecnologías utilizadas                                     {Fore.CYAN}║\n"
        f"{Fore.CYAN}║ {Fore.WHITE}   • Encuentra subdominios y más...                                        {Fore.CYAN}║\n"
        f"{Fore.CYAN}║                                                                            ║\n"
        f"{Fore.CYAN}║             {Fore.RED}  Desarrollado por VIDES_2GA_2025          {Fore.CYAN}                    ║\n"
        f"{Fore.CYAN}╚════════════════════════════════════════════════════════════════════════════╝\n"
        f"{Style.RESET_ALL}"
    )
    print(banner)
