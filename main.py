import argparse
import asyncio
import os
from time import perf_counter
from util.config_uti import Configuration
from colorama import Fore, Style
from util import engine
import pyfiglet 

# Main function to execute the code
async def Main():

    config = Configuration()
    # Parser to take the arguments
    parser = argparse.ArgumentParser(description="🕸️ Web Matrix - Comprehensive Website Security Analysis Tool | Analyze SSL, DNS, vulnerabilities, and 36+ security modules")
    parser.add_argument("-s", "--Single_Site", help="""Perform standard security analysis on a single website without NMAP scanning.
                                                    Example: python main.py -s https://example.com -m 1""")
    parser.add_argument("-sn", "--With_NMAP", help="""Perform deep security analysis including NMAP vulnerability scanning.
                                                    Requires: NMAP installed | Example: python main.py -sn https://example.com -m 1""")
    parser.add_argument("-m", "--Mode", help="""Select HTML report display theme for better readability.
                                            Options: 0 = Light Mode (white background, ideal for printing)
                                                     1 = Dark Mode (dark theme, easy on eyes, default)
                                            Example: python main.py -s https://example.com -m 0""")
    parser.add_argument("-md", "--Multi_Site", help="""Perform batch analysis on multiple websites from a text file.
                                                    File format: One URL per line (http:// or https://).
                                                    Generates separate reports for each website with individual health scores.
                                                    Example: python main.py -md websites.txt -m 1
                                                    Sample file content:
                                                        https://example1.com
                                                        https://example2.com
                                                        http://example3.org""")
    parser.add_argument("-v", "--version", help="Display Web Matrix version, author information, and system details", action="store_true")
    args = parser.parse_args()

    start_time = perf_counter()

    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    
    Terminal_header = pyfiglet.figlet_format(config.TOOL_NAME, font="ogre")
    print(Fore.CYAN + Style.BRIGHT + Terminal_header + Fore.RESET + Style.RESET_ALL)

    # print(Fore.CYAN + Style.BRIGHT + f"""\n
    #  __    __       _                                _  _  _  
    # / / /\ \ \ ___ | |__     /\ /\ _   _  _ __    __| || |(_) 
    # \ \/  \/ // _ \| '_ \   / //_/| | | || '_ \  / _` || || | 
    #  \  /\  /|  __/| |_) | / __ \ | |_| || | | || (_| || || | 
    #   \/  \/  \___||_.__/  \/  \/  \__,_||_| |_| \__,_||_||_| 
    # \n""" + Fore.RESET + Style.RESET_ALL)

    try:
        if args.Single_Site and args.Mode:
            url = args.Single_Site.strip()
            if not (url.startswith("http://")) and not (url.startswith('https://')):
                url = "https://" + url
            print(f"📡 Searching Details For : {url}", flush=True)
            addr = str(url)
            mode = args.Mode.strip()
            eng = engine.engine(addr, mode, False)
            await eng.Start_Engine()
        
        elif args.With_NMAP:
            url = args.With_NMAP.strip()
            if not (url.startswith("http://")) and not (url.startswith('https://')):
                url = "https://" + url
            print(f"📡 Searching Details For : {url}", flush=True)
            addr = str(url)
            mode = args.Mode.strip()
            eng = engine.engine(addr, mode, True)
            await eng.Start_Engine()

        elif args.Multi_Site:
            print(f"[!] Search Multi Sites Details : File Name -> {args.Multi_Site.strip()}", flush=True)
            addr = str(args.Multi_Site.strip())
            eng = engine.engine(addr)
            await eng.Start_Engine()
            
        elif args.help:
            print(Fore.CYAN + Style.BRIGHT + "\n" + "="*70)
            print(Fore.GREEN + Style.BRIGHT + "🕸️  WEB MATRIX - USAGE GUIDE")
            print(Fore.CYAN + Style.BRIGHT + "="*70 + "\n")
            
            # Usage
            print(Fore.YELLOW + Style.BRIGHT + "📋 USAGE:")
            print(Fore.WHITE + "   python main.py [-s URL | -sn URL | -md FILE] [-m MODE] [-v] [-h]\n")
            
            # Scan Options
            print(Fore.YELLOW + Style.BRIGHT + "🔍 SCAN OPTIONS:")
            print(Fore.GREEN + "   -s,  --Single_Site" + Fore.WHITE + "    Analyze single website (standard scan)")
            print(Fore.WHITE + "                          Example: python main.py -s https://example.com -m 1\n")
            
            print(Fore.GREEN + "   -sn, --With_NMAP" + Fore.WHITE + "      Analyze with NMAP vulnerability scanning")
            print(Fore.WHITE + "                          Example: python main.py -sn https://example.com -m 1\n")
            
            print(Fore.GREEN + "   -md, --Multi_Site" + Fore.WHITE + "     Batch analyze multiple websites from file")
            print(Fore.WHITE + "                          Example: python main.py -md websites.txt\n")
            
            # Display Options
            print(Fore.YELLOW + Style.BRIGHT + "🎨 DISPLAY OPTIONS:")
            print(Fore.GREEN + "   -m,  --Mode" + Fore.WHITE + "           Select report theme (0=Light, 1=Dark)")
            print(Fore.WHITE + "                          Example: python main.py -s https://example.com -m 0\n")
            
            # Information
            print(Fore.YELLOW + Style.BRIGHT + "ℹ️  INFORMATION:")
            print(Fore.GREEN + "   -v,  --version" + Fore.WHITE + "        Show program version and exit")
            print(Fore.GREEN + "   -h,  --help" + Fore.WHITE + "           Show this help message and exit\n")
            
            # Quick Examples
            print(Fore.YELLOW + Style.BRIGHT + "⚡ QUICK EXAMPLES:")
            print(Fore.CYAN + "   Standard scan:")
            print(Fore.WHITE + "      python main.py -s https://example.com -m 1\n")
            
            print(Fore.CYAN + "   Deep scan with NMAP:")
            print(Fore.WHITE + "      python main.py -sn https://example.com -m 0\n")
            
            print(Fore.CYAN + "   Batch scanning:")
            print(Fore.WHITE + "      python main.py -md websites.txt -m 1\n")
            
            print(Fore.CYAN + "   Check version:")
            print(Fore.WHITE + "      python main.py -v\n")
            
            # Output Location
            print(Fore.YELLOW + Style.BRIGHT + "📁 OUTPUT:")
            print(Fore.WHITE + "   Reports saved in: " + Fore.GREEN + "./output/" + Fore.WHITE + " directory")
            print(Fore.WHITE + "   Files: WebMatrix_[domain]_[timestamp].html\n")
            
            # Footer
            print(Fore.CYAN + Style.BRIGHT + "="*70)
            print(Fore.GREEN + Style.BRIGHT + "🚀 For more info: https://github.com/alien-c0de/web-matrix")
            print(Fore.CYAN + Style.BRIGHT + "="*70 + "\n" + Style.RESET_ALL)


            # print(Fore.GREEN + Style.BRIGHT + f"[*] Usage: main.py [-s For_Single_Website -m Multi_Website] [-v VERSION] [-h HELP]")
            # print(Fore.GREEN + Style.BRIGHT + f"[*] Options:")
            # print(Fore.GREEN + Style.BRIGHT + f"        -s, --Please Provide The Name Of The Website To Get The Details.")
            # print(Fore.GREEN + Style.BRIGHT + f"        -m, --Please Provide The List Of Websites In txt File to Get The Details.")
            # print(Fore.GREEN + Style.BRIGHT + f"        -v, --version  Show Program Version")
            # print(Fore.GREEN + Style.BRIGHT + f"        -h, --help Show This Help Message And Exit")
            # print(Fore.GREEN + Style.BRIGHT + f"[*] To execute code using the Python interpreter - python main.py -s <website name> -m <list of websites in txt file>")
            # print(Fore.GREEN + Style.BRIGHT + f"[*] To execute code using the Web_Data.exe - Web_Data -s <website name> -m <list of websites in txt file>")
            # print(Fore.GREEN + Style.BRIGHT + f"[*] Check the version - python main.py -v\n")
            
        elif args.version:
            print(Fore.GREEN + Style.BRIGHT + f"[*] {config.TOOL_NAME}  Version: " + config.VERSION + "\n")
            # print(Fore.BLUE + Style.BRIGHT + f"[*] A Python Tool To Retrieve All The Website dDetails.\n[*] Version: 1.0\n")
            print(Fore.YELLOW + Style.BRIGHT + f"[#] Author - " + config.AUTHOR +"\n")
        else:
            print("usage: python main.py [-S For_Single_Website -m Multi_Website] [-v VERSION] [-h HELP]") 
    except Exception as ex:
        error_msg = str(ex)
        msg = "[-] " + "Main Error: Reading Error, " + error_msg
        print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
        
    print(Fore.YELLOW + Style.BRIGHT + f"\n⏱️ Total Time Taken: {round(perf_counter() - start_time, 2)} Seconds.", flush=True)
    print(Style.RESET_ALL)
    if config.REPORT_FOOTER.upper() == "YES":
        print(Fore.YELLOW + f"📢 {config.FOOTER_OWNER_TITLE} {config.AUTHOR} Ver: {config.VERSION} © {config.YEAR }", flush=True)
        print(Fore.YELLOW + f"📥 {config.EMAIL} ", flush=True)
        print(Fore.YELLOW + f"🚀 {config.GITHUB}", flush=True)
        print(Style.RESET_ALL)

if __name__ == '__main__':
    asyncio.run(Main())
