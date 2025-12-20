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
    parser = argparse.ArgumentParser(description="Python Tool: WebSite Details")
    parser.add_argument("-s", "--Single_Site", help="Option To Search Single Website Details e.g. python main.py -s website_name")
    parser.add_argument("-sn", "--With_NMAP", help="Option To Search Single Website Details With Nmap e.g. python main.py -sn website_name")
    parser.add_argument("-m", "--Mode", help="Option To Select Report Display Mode e.g. python main.py -sn website_name")
    parser.add_argument("-md", "--Multi_Site", help="Option To Search Multiple Website Details e.g. python main.py -m Site_list.txt")
    parser.add_argument("-v", "--version", help="Show Tool Version", action="store_true")
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
            print(Fore.GREEN + Style.BRIGHT + f"[*] Usage: main.py [-S For_Single_Website -m Multi_Website] [-v VERSION] [-h HELP]")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Options:")
            print(Fore.GREEN + Style.BRIGHT + f"        -s, --Please Provide The Name Of The Website To Get The Details.")
            print(Fore.GREEN + Style.BRIGHT + f"        -m, --Please Provide The List Of Websites In txt File to Get The Details.")
            print(Fore.GREEN + Style.BRIGHT + f"        -v, --version  Show Program Version")
            print(Fore.GREEN + Style.BRIGHT + f"        -h, --help Show This Help Message And Exit")
            print(Fore.GREEN + Style.BRIGHT + f"[*] To execute code using the Python interpreter - python main.py -s <website name> -m <list of websites in txt file>")
            print(Fore.GREEN + Style.BRIGHT + f"[*] To execute code using the Web_Data.exe - Web_Data -s <website name> -m <list of websites in txt file>")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Check the version - python main.py -v\n")
            
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
