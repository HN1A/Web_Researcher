#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import random
import socket
import argparse
import requests
import dns.resolver
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin, quote, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from tqdm import tqdm
import xml.etree.ElementTree as ET
import re
import ssl
import ftplib
import smtplib
import paramiko
import warnings
from datetime import datetime

# Disable SSL warnings
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

warnings.filterwarnings("ignore")

class GoldenScanner:
    def __init__(self):
        # Color settings
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'bold': '\033[1m',
            'underline': '\033[4m',
            'reset': '\033[0m'
        }
        
        # Scanner configuration
        self.config = {
            'wordlists': {
                '1': {'name': 'Quick (100 items)', 'path': 'wordlists/small.txt', 'size': 'small'},
                '2': {'name': 'Balanced (1000 items)', 'path': 'wordlists/medium.txt', 'size': 'medium'},
                '3': {'name': 'Comprehensive (10000 items)', 'path': 'wordlists/full.txt', 'size': 'large'},
                '4': {'name': 'Custom', 'path': None, 'size': 'custom'}
            },
            'admin_pages': [
                'admin', 'administrator', 'wp-admin', 'wp-login', 
                'login', 'panel', 'controlpanel', 'manager',
                'backend', 'cms', 'admincp', 'userlogin',
                'admin.php', 'admin.asp', 'admin.jsp',
                'admin_area', 'admin-login', 'admin_login',
                'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
                'adm', 'admlogin', 'adminpanel', 'admin_area',
                'admin-login.php', 'admin-login.asp', 'admin-login.jsp',
                'adminarea', 'bb-admin', 'blog/wp-admin',
                'controlpanel', 'cp', 'dashboard', 'loginadmin',
                'memberadmin', 'members', 'modelsearch/admin',
                'moderator', 'moderator/admin', 'myadmin',
                'pages/admin/admin-login', 'panel-administracion',
                'phpMyAdmin', 'phpmyadmin', 'sysadmin', 'user',
                'administratorlogin', 'admins', 'authentication',
                'auth', 'account', 'accounts', 'adminlogin',
                'administration', 'admincontrol', 'admincontrols',
                'admincp/login.asp', 'admincp/login.php',
                'administratoraccounts', 'administratorlogin',
                'adminsql', 'advanced_admin', 'ajaxpro',
                'album_portal', 'app/admin', 'authadmin',
                'authoradmin', 'b2evolution/admin', 'base/admin',
                'bb-admin/index.php', 'bb-admin/login.php',
                'bigadmin', 'blogadmin', 'blogger/admin',
                'bo/login.asp', 'bo/login.php', 'cPanel',
                'cms/admin', 'content/admin', 'control',
                'core/admin', 'customer/admin', 'databaseadmin',
                'directadmin', 'dir-login', 'editadmin',
                'fileadmin', 'folderadmin', 'formsadmin',
                'forum/admin', 'forumadministrator', 'home/admin',
                'hosting-admin', 'httpadmin', 'indadmin',
                'install/admin', 'joomla/administrator',
                'jsps/admin', 'ldapadmin', 'liveadmin',
                'login_db', 'login_admin', 'login1',
                'login2', 'login3', 'login4', 'login5',
                'logins', 'madmin', 'management',
                'manager/admin', 'memberadmin', 'membersadmin',
                'meta_login', 'modelsearch/admin', 'moderator',
                'mysql/admin', 'navSiteAdmin', 'newsadmin',
                'nsw/admin/login', 'opencart/admin', 'pages/admin',
                'paneladmin', 'panel-administracion/login.php',
                'panel-administracion/index.php', 'phpadmin',
                'phpldapadmin', 'phppgadmin', 'phpSQLiteAdmin',
                'platz_login', 'power_user', 'productadmin',
                'project-admins', 'pureadmin', 'radmind',
                'radmind-1', 'rcjakar/admin', 'release_admin',
                'root', 'rstudio', 'server_admin', 'serveradmin',
                'setup', 'siteadmin', 'sitemanager',
                'smblogin', 'sql-admin', 'sspanel',
                'staradmin', 'sub-login', 'superadmin',
                'superuser', 'support_login', 'sysadm',
                'system_administration', 'system-administration',
                'typo3', 'ur-admin', 'useradmin',
                'usradmin', 'vadmind', 'vmailadmin',
                'webadmin', 'wizmysqladmin', 'wp-login.php',
                'wp-admin/admin-ajax.php', 'wp-admin/admin-post.php',
                'wp-admin/admin.php', 'wp-admin/index.php',
                'wp-admin/install.php', 'wp-admin/login.php',
                'wp-admin/setup-config.php', 'wp-login',
                'wp/wp-admin', 'wp/wp-admin/admin-ajax.php',
                'wp/wp-includes', 'xlogin', 'yonet',
                'yonetici', 'yonetici.asp', 'yonetici.php',
                'zadmin', 'zentrack', '_admin', '_adm',
                '_login', '_vti_bin', '_vti_cnf',
                '_vti_log', '_vti_pvt', '_vti_txt'
            ],
            'common_ports': [21, 22, 80, 443, 8080, 8443, 3306, 5432, 3389, 5900],
            'stealth_mode': True,
            'max_threads': 5,
            'delay_range': (1, 3),
            'timeout': 10,
            'scan_depth': 2,
            'cert_verify': False,
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
            ]
        }
        
        # Session settings
        self.ua = UserAgent()
        self.session = self._create_secure_session()
        self.scan_results = {
            'target': '',
            'start_time': '',
            'end_time': '',
            'duration': '',
            'files': [],
            'paths': [],
            'vulnerabilities': {},
            'ports': [],
            'headers': {},
            'dns': {},
            'technologies': [],
            'sitemap': [],
            'emails': [],
            'comments': [],
            'hidden_params': [],
            'server_info': {},
            'security_measures': []
        }
        
    def _show_loading_animation(self, duration=10):
        """Display loading animation with spinning slash"""
        symbols = ['|', '/', '-', '\\']
        end_time = time.time() + duration
        i = 0
        
        print(f"\n{self.colors['yellow']}Initializing Golden Scanner V1.0...{self.colors['reset']}")
        print(f"{self.colors['cyan']}Please wait while we prepare the ultimate scanning experience{self.colors['reset']}")
        
        while time.time() < end_time:
            sys.stdout.write(f"\r{self.colors['green']}Loading {symbols[i % len(symbols)]} {self.colors['reset']}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        
        # Clear screen after loading
        self._clear_screen()
        time.sleep(3)  # Wait 3 seconds before showing main art
        
    def _clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def _show_launch_sequence(self):
        """Display the complete launch sequence with artwork"""
        # First show the original banner
        self._print_banner()
        
        # Show loading animation for 10 seconds
        self._show_loading_animation()
        
        # After clearing screen, show the new artwork
        self._print_new_art()
        
    def _print_new_art(self):
        """Display the new requested artwork"""
        new_art = f"""
{self.colors['red']}
⠀⠀⠀⠀⠀⠠⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢈⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣴⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣴⣿⡷⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣾⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣧⠀⠀⠀⠘⣦⡀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡇⠀⠀⠀⢀⣼⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠹⣿⣿⣿⣷⣦⣄⡀⣿⣱⡀⠀⠀⠀⠀⠀⠀⢸⢿⣧⣠⣴⣾⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⠛⢷⣿⣟⡿⠿⠿⡟⣓⣒⣛⡛⡛⢟⣛⡛⠟⠿⣻⢿⣿⣻⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢠⣴⢻⡭⠖⡉⠥⣈⠀⣐⠂⡄⠔⢂⢦⡹⢬⡕⠊⠳⠈⢿⣳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣼⣷⣋⠲⢮⣁⠀⣐⠆⡤⢊⣜⡀⡾⣀⠀⢠⢻⣌⣤⣥⣓⣌⢻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⣟⣽⢳⣯⣝⣦⡀⠓⡤⢆⠇⠂⠄⠤⡝⣂⠋⠖⢋⠀⣡⣶⣾⡿⡷⣽⡿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⡜⢯⣿⣿⣿⣷⣿⣤⣧⣶⣬⣝⣃⣓⣈⣥⣶⣿⣾⣿⣿⢣⠇⢻⡞⣯⣹⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢻⣼⣯⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡔⡯⢧⢟⣟⣱⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⡼⡼⢁⡌⢼⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣿⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⢇⡼⢃⡿⣼⣛⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⠟⣡⣫⣢⢏⣼⡵⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣏⢿⣿⣿⣿⣿⣿⣿⡿⢿⣿⡾⢕⣻⣽⣵⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠘⢷⣮⣿⡼⢭⡟⠳⠞⡖⢛⣶⣷⣯⡶⠟⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⠛⠛⠛⠿⠟⠛⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀
{self.colors['reset']}
{self.colors['yellow']}{'═'*80}{self.colors['reset']}
{self.colors['cyan']}𝔻𝕖𝕧𝕖𝕝𝕠𝕡𝕖𝕣: ✨آلَمًهّيَبً✨{self.colors['reset']}
{self.colors['cyan']}𝕋𝕚𝕜𝕋𝕠𝕜: m_m_h_b1{self.colors['reset']}
{self.colors['cyan']}𝕋𝕖𝕝𝕖𝕘𝕣𝕒𝕞:@GUP_89{self.colors['reset']}
{self.colors['yellow']}{'═'*80}{self.colors['reset']}
"""
        print(new_art)
        
    def _create_secure_session(self):
        """Create a secure session with custom settings"""
        session = requests.Session()
        session.verify = self.config['cert_verify']
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'DNT': '1'
        })
        return session
        
    def _random_delay(self):
        """Random delay for stealth mode"""
        if self.config['stealth_mode']:
            time.sleep(random.uniform(*self.config['delay_range']))
            
    def _get_random_headers(self):
        """Generate random HTTP headers"""
        return {
            'User-Agent': random.choice(self.config['user_agents']),
            'Referer': random.choice([
                'https://www.google.com/',
                'https://www.bing.com/',
                'https://www.yahoo.com/',
                'https://www.facebook.com/'
            ]),
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
        
    def _print_banner(self):
        """Display the tool banner"""
        banner = f"""
{self.colors['red']}{self.colors['bold']}
╔════════════════════════════════════════════════════════════════════════════╗
║ ██████╗  ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗████████╗███████╗      ║
║ ██╔══██╗██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝      ║
║ ██║  ██║██║   ██║██║     ██║  ██║█████╗  ██╔██╗ ██║   ██║   █████╗        ║
║ ██║  ██║██║   ██║██║     ██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██╔══╝        ║
║ ██████╔╝╚██████╔╝███████╗██████╔╝███████╗██║ ╚████║   ██║   ███████╗      ║
║ ╚═════╝  ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝      ║
╠────────────────────────────────────────────────────────────────────────────╣
║ {self.colors['yellow']}Golden Web Vulnerability Scanner - Ultimate Edition V1.0{self.colors['red']}       ║
╚════════════════════════════════════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(banner)
    
    def _print_menu(self):
        """Display the main menu"""
        menu = f"""
{self.colors['green']}{self.colors['bold']}
╔════════════════════════════════════════════╗
║           {self.colors['yellow']}MAIN SCANNER MENU{self.colors['green']}               ║
╠════════════════════════════════════════════╣
║ {self.colors['cyan']}1{self.colors['green']}. Scan for Sensitive Files (Stealth)      ║
║ {self.colors['cyan']}2{self.colors['green']}. Check HTTP Security Headers            ║
║ {self.colors['cyan']}3{self.colors['green']}. Discover Admin Pages                   ║
║ {self.colors['cyan']}4{self.colors['green']}. Scan for Common Vulnerabilities        ║
║ {self.colors['cyan']}5{self.colors['green']}. Check Open Ports                      ║
║ {self.colors['cyan']}6{self.colors['green']}. Extract Website Paths                  ║
║ {self.colors['cyan']}7{self.colors['green']}. Identify Website Technologies         ║
║ {self.colors['cyan']}8{self.colors['green']}. Perform DNS Reconnaissance            ║
║ {self.colors['cyan']}9{self.colors['green']}. Comprehensive Stealth Scan            ║
║ {self.colors['cyan']}10{self.colors['green']}. Extract Emails & Comments            ║
║ {self.colors['cyan']}11{self.colors['green']}. Show Server & Security Info          ║
║ {self.colors['cyan']}0{self.colors['green']}. Exit                                  ║
╚════════════════════════════════════════════╝
{self.colors['reset']}
"""
        print(menu)
    
    def _print_status(self, message, status='info'):
        """Print status messages with color coding"""
        colors = {
            'info': self.colors['cyan'],
            'success': self.colors['green'],
            'warning': self.colors['yellow'],
            'error': self.colors['red']
        }
        print(f"{colors.get(status, self.colors['cyan'])}[*] {message}{self.colors['reset']}")
        
    def _show_wordlist_menu(self):
        """Display wordlist selection menu"""
        print(f"\n{self.colors['purple']}{self.colors['bold']}")
        print("╔════════════════════════════════════════════╗")
        print("║       Select Wordlist for Scanning         ║")
        print("╠════╦══════════════════════╦═════════════╣")
        print("║ ID ║        Name          ║    Size     ║")
        print("╠════╬══════════════════════╬═════════════╣")
        for key, value in self.config['wordlists'].items():
            print(f"║ {self.colors['cyan']}{key.ljust(2)}{self.colors['purple']} ║ {value['name'].ljust(20)} ║ {value['size'].ljust(11)} ║")
        print("╚════╩══════════════════════╩═════════════╝")
        print(self.colors['reset'])
        
        choice = input(f"{self.colors['yellow']}Select wordlist (1-4): {self.colors['reset']}")
        if choice not in self.config['wordlists']:
            self._print_status("Invalid selection!", 'error')
            return None
            
        if choice == '4':
            custom_path = input(f"{self.colors['yellow']}Enter custom wordlist path: {self.colors['reset']}")
            if not Path(custom_path).exists():
                self._print_status("File not found!", 'error')
                return None
            return custom_path
            
        return self.config['wordlists'][choice]['path']

    def scan_sensitive_files(self, url, wordlist_path):
        """Scan for sensitive files using wordlist"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                words = f.read().splitlines()
                
            self._print_status(f"Starting stealth scan for sensitive files with {len(words)} items...", 'info')
            
            found_files = []
            progress = tqdm(total=len(words), desc="Scanning Files", unit="file", 
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
            
            def check_file(word):
                self._random_delay()
                target_url = f"{url}/{word}".replace('//', '/')
                try:
                    headers = self._get_random_headers()
                    response = self.session.get(target_url, headers=headers, 
                                              timeout=self.config['timeout'], 
                                              allow_redirects=False)
                    if response.status_code == 200:
                        file_type = response.headers.get('Content-Type', 'unknown')
                        size = len(response.content)
                        found_files.append({
                            'url': target_url,
                            'type': file_type,
                            'size': size,
                            'status': response.status_code
                        })
                        progress.write(f"{self.colors['green']}[+] Found: {target_url} | Type: {file_type} | Size: {size} bytes{self.colors['reset']}")
                except Exception as e:
                    pass
                finally:
                    progress.update(1)
            
            with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
                futures = [executor.submit(check_file, word) for word in words]
                for future in as_completed(futures):
                    future.result()
            
            progress.close()
            self.scan_results['files'] = found_files
            return found_files
                
        except Exception as e:
            self._print_status(f"Error occurred: {e}", 'error')
            return []
    
    def extract_paths(self, url):
        """Extract all website paths with deep scanning"""
        try:
            self._print_status("Starting deep website path extraction...", 'info')
            
            visited = set()
            paths = set()
            queue = [(url, 0)]
            
            progress = tqdm(desc="Extracting Paths", unit="path",
                          bar_format="{l_bar}{bar}| {n_fmt} paths [{elapsed}]")
            
            while queue:
                current_url, current_depth = queue.pop(0)
                
                if current_depth > self.config['scan_depth']:
                    continue
                    
                if current_url in visited:
                    continue
                    
                visited.add(current_url)
                
                try:
                    self._random_delay()
                    headers = self._get_random_headers()
                    response = self.session.get(current_url, headers=headers, 
                                             timeout=self.config['timeout'])
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        # Filter unwanted links
                        if not full_url.startswith(url):
                            continue
                            
                        # Remove fragments
                        clean_url = full_url.split('#')[0]
                        
                        # Add path if new
                        if clean_url not in paths:
                            paths.add(clean_url)
                            progress.update(1)
                            progress.write(f"{self.colors['blue']}[*] Discovered: {clean_url}{self.colors['reset']}")
                            queue.append((clean_url, current_depth + 1))
                            
                except Exception as e:
                    continue
            
            progress.close()
            self.scan_results['paths'] = sorted(paths)
            return sorted(paths)
            
        except Exception as e:
            self._print_status(f"Error during path extraction: {e}", 'error')
            return []
    
    def scan_http_headers(self, url):
        """Check HTTP security headers"""
        try:
            self._print_status("Checking HTTP security headers...", 'info')
            
            self._random_delay()
            headers = self._get_random_headers()
            response = self.session.get(url, headers=headers, 
                                     timeout=self.config['timeout'])
            
            security_headers = {
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'missing'),
                'X-Frame-Options': response.headers.get('X-Frame-Options', 'missing'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'missing'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'missing'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'missing'),
                'Referrer-Policy': response.headers.get('Referrer-Policy', 'missing'),
                'Feature-Policy': response.headers.get('Feature-Policy', 'missing'),
                'Permissions-Policy': response.headers.get('Permissions-Policy', 'missing'),
                'Server': response.headers.get('Server', 'unknown'),
                'X-Powered-By': response.headers.get('X-Powered-By', 'unknown')
            }
            
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Security Header Results ════════{self.colors['reset']}")
            for header, value in security_headers.items():
                color = self.colors['green'] if value != 'missing' else self.colors['red']
                print(f"{self.colors['cyan']}{header.ljust(25)}: {color}{value}{self.colors['reset']}")
            
            self.scan_results['headers'] = security_headers
            return security_headers
            
        except Exception as e:
            self._print_status(f"Error checking headers: {e}", 'error')
            return {}
    
    def scan_admin_pages(self, url):
        """Discover hidden admin pages with enhanced detection"""
        try:
            self._print_status("Scanning for admin pages with enhanced detection...", 'info')
            
            found_pages = []
            progress = tqdm(total=len(self.config['admin_pages']), 
                          desc="Checking Admin Pages", unit="page",
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
            
            def check_admin_page(page):
                self._random_delay()
                target_url = f"{url}/{page}".replace('//', '/')
                try:
                    headers = self._get_random_headers()
                    response = self.session.get(target_url, headers=headers, 
                                              timeout=self.config['timeout'], 
                                              allow_redirects=False)
                    
                    # Enhanced detection logic
                    if response.status_code == 200:
                        # Check for common admin page indicators
                        content = response.text.lower()
                        admin_indicators = [
                            'admin', 'login', 'password', 'username',
                            'control panel', 'dashboard', 'administrator',
                            'wp-login', 'cpanel', 'backend'
                        ]
                        
                        # Calculate match score
                        match_score = sum(1 for indicator in admin_indicators if indicator in content)
                        
                        # If score is high enough or page size is reasonable
                        if match_score >= 2 or (len(response.content) > 1000 and len(response.content) < 50000):
                            found_pages.append({
                                'url': target_url,
                                'status': response.status_code,
                                'size': len(response.content),
                                'score': match_score,
                                'content_type': response.headers.get('Content-Type', 'unknown')
                            })
                            progress.write(f"{self.colors['green']}[+] Admin page found: {target_url} (Score: {match_score}){self.colors['reset']}")
                            
                    # Also check for 403 Forbidden (common for protected admin pages)
                    elif response.status_code == 403:
                        found_pages.append({
                            'url': target_url,
                            'status': response.status_code,
                            'size': len(response.content),
                            'score': 1,
                            'content_type': response.headers.get('Content-Type', 'unknown')
                        })
                        progress.write(f"{self.colors['yellow']}[!] Potential admin page (403): {target_url}{self.colors['reset']}")
                        
                except Exception as e:
                    pass
                finally:
                    progress.update(1)
            
            with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
                futures = [executor.submit(check_admin_page, page) for page in self.config['admin_pages']]
                for future in as_completed(futures):
                    future.result()
            
            progress.close()
            
            if not found_pages:
                self._print_status("No admin pages discovered", 'warning')
            else:
                # Sort by match score
                found_pages.sort(key=lambda x: x['score'], reverse=True)
                
                # Print summary
                print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Admin Page Scan Summary ════════{self.colors['reset']}")
                print(f"{self.colors['cyan']}Total Admin Pages Found: {len(found_pages)}{self.colors['reset']}")
                print(f"{self.colors['cyan']}Top Potential Admin Pages:{self.colors['reset']}")
                
                for i, page in enumerate(found_pages[:5], 1):
                    status_color = self.colors['green'] if page['status'] == 200 else self.colors['yellow']
                    print(f"{self.colors['cyan']}{i}. {page['url']}")
                    print(f"   Status: {status_color}{page['status']}{self.colors['reset']} | Size: {page['size']} bytes")
                    print(f"   Content-Type: {page['content_type']} | Confidence Score: {page['score']}\n")
                
            return found_pages
            
        except Exception as e:
            self._print_status(f"Error scanning admin pages: {e}", 'error')
            return []
    
    def scan_vulnerabilities(self, url):
        """Scan for common web vulnerabilities"""
        try:
            self._print_status("Starting vulnerability scan...", 'info')
            
            test_urls = self._generate_test_urls(url)
            vulnerabilities = {
                'XSS': {'found': False, 'details': []},
                'SQL Injection': {'found': False, 'details': []},
                'RCE': {'found': False, 'details': []},
                'LFI': {'found': False, 'details': []},
                'IDOR': {'found': False, 'details': []},
                'XXE': {'found': False, 'details': []},
                'SSRF': {'found': False, 'details': []},
                'CSRF': {'found': False, 'details': []}
            }
            
            progress = tqdm(total=len(test_urls.items()), 
                          desc="Testing Vulnerabilities", unit="test",
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
            
            for vuln_type, test_data in test_urls.items():
                self._random_delay()
                try:
                    headers = self._get_random_headers()
                    
                    if vuln_type == 'XXE':
                        # Test XXE vulnerability with XML
                        headers['Content-Type'] = 'application/xml'
                        response = self.session.post(test_data['url'], 
                                                    data=test_data['payload'], 
                                                    headers=headers, 
                                                    timeout=self.config['timeout'])
                        
                        if 'XXE_TEST' in response.text:
                            vulnerabilities['XXE']['found'] = True
                            vulnerabilities['XXE']['details'].append({
                                'url': test_data['url'],
                                'payload': test_data['payload'],
                                'response': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            })
                            progress.write(f"{self.colors['red']}[!] Possible XXE at: {test_data['url']}{self.colors['reset']}")
                    
                    else:
                        response = self.session.get(test_data['url'], headers=headers, 
                                                  timeout=self.config['timeout'])
                        
                        if vuln_type == 'XSS' and '<script>alert("XSS")</script>' in response.text:
                            vulnerabilities['XSS']['found'] = True
                            vulnerabilities['XSS']['details'].append({
                                'url': test_data['url'],
                                'payload': test_data['payload'],
                                'response': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            })
                            progress.write(f"{self.colors['red']}[!] Possible XSS at: {test_data['url']}{self.colors['reset']}")
                        
                        elif vuln_type == 'SQL Injection' and "error in your SQL syntax" in response.text.lower():
                            vulnerabilities['SQL Injection']['found'] = True
                            vulnerabilities['SQL Injection']['details'].append({
                                'url': test_data['url'],
                                'payload': test_data['payload'],
                                'response': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            })
                            progress.write(f"{self.colors['red']}[!] Possible SQLi at: {test_data['url']}{self.colors['reset']}")
                        
                        elif vuln_type == 'RCE' and "RCE_TEST" in response.text:
                            vulnerabilities['RCE']['found'] = True
                            vulnerabilities['RCE']['details'].append({
                                'url': test_data['url'],
                                'payload': test_data['payload'],
                                'response': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            })
                            progress.write(f"{self.colors['red']}[!] Possible RCE at: {test_data['url']}{self.colors['reset']}")
                        
                        elif vuln_type == 'LFI' and "root:" in response.text:
                            vulnerabilities['LFI']['found'] = True
                            vulnerabilities['LFI']['details'].append({
                                'url': test_data['url'],
                                'payload': test_data['payload'],
                                'response': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            })
                            progress.write(f"{self.colors['red']}[!] Possible LFI at: {test_data['url']}{self.colors['reset']}")
                        
                        elif vuln_type == 'IDOR':
                            response2 = self.session.get(test_data['url'].replace('id=1', 'id=2'), 
                                                        headers=headers, 
                                                        timeout=self.config['timeout'])
                            if response.status_code == 200 and response2.status_code == 200 and response.text == response2.text:
                                vulnerabilities['IDOR']['found'] = True
                                vulnerabilities['IDOR']['details'].append({
                                    'url': test_data['url'],
                                    'payload': test_data['payload'],
                                    'response': "Accessed different user data with same permissions"
                                })
                                progress.write(f"{self.colors['red']}[!] Possible IDOR at: {test_data['url']}{self.colors['reset']}")
                        
                        elif vuln_type == 'SSRF':
                            if "SSRF_TEST" in response.text:
                                vulnerabilities['SSRF']['found'] = True
                                vulnerabilities['SSRF']['details'].append({
                                    'url': test_data['url'],
                                    'payload': test_data['payload'],
                                    'response': response.text[:200] + '...' if len(response.text) > 200 else response.text
                                })
                                progress.write(f"{self.colors['red']}[!] Possible SSRF at: {test_data['url']}{self.colors['reset']}")
                        
                        elif vuln_type == 'CSRF':
                            if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
                                vulnerabilities['CSRF']['found'] = True
                                vulnerabilities['CSRF']['details'].append({
                                    'url': test_data['url'],
                                    'payload': "Missing CSRF protection tokens",
                                    'response': "No CSRF tokens detected in forms"
                                })
                                progress.write(f"{self.colors['red']}[!] Possible CSRF vulnerability at: {test_data['url']}{self.colors['reset']}")
                
                except Exception as e:
                    pass
                finally:
                    progress.update(1)
            
            progress.close()
            self.scan_results['vulnerabilities'] = vulnerabilities
            return vulnerabilities
            
        except Exception as e:
            self._print_status(f"Error during vulnerability scan: {e}", 'error')
            return {}
    
    def _generate_test_urls(self, base_url):
        """Generate test URLs for vulnerability scanning"""
        sql_payload = quote("' OR '1'='1")
        xss_payload = quote('<script>alert("XSS")</script>')
        rce_payload = quote('; echo "RCE_TEST";')
        lfi_payload = quote('../../../../etc/passwd')
        
        return {
            'XSS': {
                'url': f"{base_url}?q={xss_payload}",
                'payload': '<script>alert("XSS")</script>'
            },
            'SQL Injection': {
                'url': f"{base_url}?id={sql_payload}",
                'payload': "' OR '1'='1"
            },
            'RCE': {
                'url': f"{base_url}?cmd={rce_payload}",
                'payload': '; echo "RCE_TEST";'
            },
            'LFI': {
                'url': f"{base_url}?file={lfi_payload}",
                'payload': '../../../../etc/passwd'
            },
            'IDOR': {
                'url': f"{base_url}/profile?id=1",
                'payload': 'Change user ID to 2'
            },
            'XXE': {
                'url': base_url,
                'payload': """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;XXE_TEST</foo>"""
            },
            'SSRF': {
                'url': f"{base_url}?url=http://localhost/admin",
                'payload': 'http://localhost/admin'
            },
            'CSRF': {
                'url': base_url,
                'payload': 'Check for missing CSRF tokens'
            }
        }
    
    def scan_ports(self, host):
        """Scan for open ports on target host"""
        try:
            self._print_status(f"Scanning ports on {host}...", 'info')
            
            open_ports = []
            progress = tqdm(total=len(self.config['common_ports']), 
                          desc="Port Scanning", unit="port",
                          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
            
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = 'unknown'
                        
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'status': 'open'
                        })
                        progress.write(f"{self.colors['green']}[+] Port {port} open ({service}){self.colors['reset']}")
                    sock.close()
                except Exception as e:
                    pass
                finally:
                    progress.update(1)
            
            with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
                futures = [executor.submit(check_port, port) for port in self.config['common_ports']]
                for future in as_completed(futures):
                    future.result()
            
            progress.close()
            
            if not open_ports:
                self._print_status("No open ports found", 'warning')
            
            self.scan_results['ports'] = open_ports
            return open_ports
            
        except Exception as e:
            self._print_status(f"Error during port scan: {e}", 'error')
            return []
    
    def scan_technologies(self, url):
        """Identify technologies used by the website"""
        try:
            self._print_status("Identifying website technologies...", 'info')
            
            technologies = []
            headers = self._get_random_headers()
            response = self.session.get(url, headers=headers, 
                                     timeout=self.config['timeout'])
            
            # Check web server
            server = response.headers.get('Server', '')
            if server:
                technologies.append({
                    'type': 'Web Server',
                    'name': server,
                    'confidence': 'high'
                })
            
            # Check programming language
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                technologies.append({
                    'type': 'Programming Language',
                    'name': powered_by,
                    'confidence': 'medium'
                })
            
            # Check CMS
            if 'wp-content' in response.text:
                technologies.append({
                    'type': 'CMS',
                    'name': 'WordPress',
                    'confidence': 'high'
                })
            elif 'Joomla' in response.text:
                technologies.append({
                    'type': 'CMS',
                    'name': 'Joomla',
                    'confidence': 'high'
                })
            elif 'Drupal' in response.text:
                technologies.append({
                    'type': 'CMS',
                    'name': 'Drupal',
                    'confidence': 'high'
                })
            
            # Check JavaScript libraries
            if 'jquery' in response.text.lower():
                technologies.append({
                    'type': 'JavaScript Library',
                    'name': 'jQuery',
                    'confidence': 'medium'
                })
            if 'react' in response.text.lower():
                technologies.append({
                    'type': 'JavaScript Framework',
                    'name': 'React',
                    'confidence': 'medium'
                })
            
            # Check for common frameworks
            if 'laravel' in response.text.lower():
                technologies.append({
                    'type': 'PHP Framework',
                    'name': 'Laravel',
                    'confidence': 'medium'
                })
            if 'django' in response.text.lower():
                technologies.append({
                    'type': 'Python Framework',
                    'name': 'Django',
                    'confidence': 'medium'
                })
            
            # Display results
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Discovered Technologies ════════{self.colors['reset']}")
            for tech in technologies:
                print(f"{self.colors['cyan']}{tech['type'].ljust(20)}: {self.colors['green']}{tech['name']} {self.colors['yellow']}(confidence: {tech['confidence']}){self.colors['reset']}")
            
            self.scan_results['technologies'] = technologies
            return technologies
            
        except Exception as e:
            self._print_status(f"Error identifying technologies: {e}", 'error')
            return []
    
    def scan_dns(self, domain):
        """Perform DNS reconnaissance on target domain"""
        try:
            self._print_status(f"Performing DNS reconnaissance on {domain}...", 'info')
            
            dns_records = {
                'A': [],
                'AAAA': [],
                'MX': [],
                'NS': [],
                'TXT': [],
                'CNAME': []
            }
            
            # Check A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for rdata in answers:
                    dns_records['A'].append(str(rdata))
            except:
                pass
            
            # Check AAAA records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                for rdata in answers:
                    dns_records['AAAA'].append(str(rdata))
            except:
                pass
            
            # Check MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                for rdata in answers:
                    dns_records['MX'].append({
                        'preference': rdata.preference,
                        'exchange': str(rdata.exchange)
                    })
            except:
                pass
            
            # Check NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                for rdata in answers:
                    dns_records['NS'].append(str(rdata))
            except:
                pass
            
            # Check TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    dns_records['TXT'].append(str(rdata))
            except:
                pass
            
            # Check CNAME records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    dns_records['CNAME'].append(str(rdata))
            except:
                pass
            
            # Display results
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ DNS Records ════════{self.colors['reset']}")
            
            for record_type, records in dns_records.items():
                if records:
                    if not isinstance(records[0], dict):
                        records_str = ', '.join(str(r) for r in records)
                    else:
                        records_str = ', '.join(
                            f"{r['exchange']} (pref: {r['preference']})" 
                            for r in records
                        )
                    
                    print(
                        f"{self.colors['cyan']}{record_type.ljust(10)}: "
                        f"{self.colors['green']}{records_str}"
                        f"{self.colors['reset']}"
                    )
                else:
                    print(
                        f"{self.colors['cyan']}{record_type.ljust(10)}: "
                        f"{self.colors['red']}Not found"
                        f"{self.colors['reset']}"
                    )
            
            self.scan_results['dns'] = dns_records
            return dns_records
            
        except Exception as e:
            self._print_status(f"Error during DNS scan: {e}", 'error')
            return {}
    
    def extract_emails_comments(self, url):
        """Extract emails and comments from website pages"""
        try:
            self._print_status("Extracting emails and comments from website...", 'info')
            
            emails = set()
            comments = []
            
            # First get the main page
            self._random_delay()
            headers = self._get_random_headers()
            response = self.session.get(url, headers=headers, 
                                     timeout=self.config['timeout'])
            
            # Extract from main page
            self._extract_from_content(response.text, url, emails, comments)
            
            # Now scan up to 10 additional pages
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [a.get('href') for a in soup.find_all('a', href=True)]
            scanned_pages = 0
            
            for link in links:
                if scanned_pages >= 10:
                    break
                    
                full_url = urljoin(url, link)
                if full_url.startswith(url):
                    try:
                        self._random_delay()
                        page_response = self.session.get(full_url, headers=headers,
                                                      timeout=self.config['timeout'])
                        self._extract_from_content(page_response.text, full_url, emails, comments)
                        scanned_pages += 1
                    except:
                        continue
            
            # Store results
            self.scan_results['emails'] = list(emails)
            self.scan_results['comments'] = comments
            
            # Display results
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Extracted Emails ════════{self.colors['reset']}")
            for email in emails:
                print(f"{self.colors['cyan']}- {email}{self.colors['reset']}")
            
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Extracted Comments ════════{self.colors['reset']}")
            for comment in comments:
                print(f"{self.colors['cyan']}From {comment['page']}:")
                print(f"{self.colors['green']}{comment['content']}{self.colors['reset']}\n")
            
            return {
                'emails': list(emails),
                'comments': comments
            }
            
        except Exception as e:
            self._print_status(f"Error extracting emails/comments: {e}", 'error')
            return {'emails': [], 'comments': []}
    
    def _extract_from_content(self, content, page_url, emails, comments):
        """Helper function to extract emails and comments from page content"""
        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        found_emails = re.findall(email_pattern, content)
        for email in found_emails:
            emails.add(email)
        
        # Extract HTML comments
        soup = BeautifulSoup(content, 'html.parser')
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text):
            comments.append({
                'page': page_url,
                'content': comment.strip()
            })
        
        # Extract JavaScript comments
        js_comments = re.findall(r'//.*?$|/\*.*?\*/', content, re.DOTALL | re.MULTILINE)
        for comment in js_comments:
            comments.append({
                'page': page_url,
                'content': comment.strip()
            })
    
    def get_server_info(self, url):
        """Get server information including IP and hosting provider"""
        try:
            self._print_status("Gathering server information...", 'info')
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Get IP address
            try:
                ip_address = socket.gethostbyname(domain)
            except:
                ip_address = "Unknown"
            
            # Get server headers
            headers = self._get_random_headers()
            response = self.session.get(url, headers=headers, timeout=self.config['timeout'])
            
            server_info = {
                'domain': domain,
                'ip_address': ip_address,
                'server': response.headers.get('Server', 'Unknown'),
                'x_powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'hosting_provider': self._detect_hosting_provider(ip_address),
                'technologies': self._detect_technologies(response)
            }
            
            self.scan_results['server_info'] = server_info
            
            # Print results
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Server Information ════════{self.colors['reset']}")
            print(f"{self.colors['cyan']}Domain:{self.colors['reset']} {server_info['domain']}")
            print(f"{self.colors['cyan']}IP Address:{self.colors['reset']} {server_info['ip_address']}")
            print(f"{self.colors['cyan']}Server:{self.colors['reset']} {server_info['server']}")
            print(f"{self.colors['cyan']}X-Powered-By:{self.colors['reset']} {server_info['x_powered_by']}")
            print(f"{self.colors['cyan']}Hosting Provider:{self.colors['reset']} {server_info['hosting_provider']}")
            
            return server_info
            
        except Exception as e:
            self._print_status(f"Error getting server info: {e}", 'error')
            return {}

    def _detect_hosting_provider(self, ip_address):
        """Try to detect hosting provider from IP"""
        try:
            if ip_address == "Unknown":
                return "Unknown"
                
            # Simple IP-based detection (can be enhanced with API calls)
            if ip_address.startswith(('104.', '108.', '172.', '192.')):
                return "Likely AWS"
            elif ip_address.startswith(('136.', '66.', '67.', '69.')):
                return "Likely Google Cloud"
            elif ip_address.startswith(('13.', '40.', '51.', '52.')):
                return "Likely Azure"
            elif ip_address.startswith(('185.', '94.', '95.')):
                return "Likely DigitalOcean"
            elif ip_address.startswith(('45.', '65.', '66.')):
                return "Likely Linode"
            else:
                return "Unknown (possibly dedicated server)"
        except:
            return "Unknown"

    def check_security_measures(self, url):
        """Check various security measures on the website"""
        try:
            self._print_status("Checking security measures...", 'info')
            
            security_measures = []
            
            # Get headers first
            headers = self.scan_http_headers(url)
            
            # Check for WAF
            waf = self._detect_waf(url)
            security_measures.append({
                'name': 'Web Application Firewall',
                'status': waf if waf else 'Not detected',
                'protection_level': 'High' if waf else 'Low'
            })
            
            # Check SSL/TLS
            ssl_info = self._check_ssl(url)
            security_measures.append({
                'name': 'SSL/TLS',
                'status': ssl_info['status'],
                'protection_level': ssl_info['protection_level']
            })
            
            # Check security headers
            missing_headers = [h for h, v in headers.items() if v == 'missing']
            security_measures.append({
                'name': 'Security Headers',
                'status': f"Missing {len(missing_headers)} of 8 key headers" if missing_headers else 'All key headers present',
                'protection_level': 'High' if not missing_headers else 'Medium' if len(missing_headers) < 4 else 'Low'
            })
            
            # Check for rate limiting
            rate_limit = self._check_rate_limiting(url)
            security_measures.append({
                'name': 'Rate Limiting',
                'status': 'Detected' if rate_limit else 'Not detected',
                'protection_level': 'High' if rate_limit else 'Medium'
            })
            
            # Store results
            self.scan_results['security_measures'] = security_measures
            
            # Print results
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Security Measures ════════{self.colors['reset']}")
            for measure in security_measures:
                color = self.colors['green'] if measure['protection_level'] == 'High' else self.colors['yellow'] if measure['protection_level'] == 'Medium' else self.colors['red']
                print(f"{self.colors['cyan']}{measure['name'].ljust(20)}: {color}{measure['status']} {self.colors['yellow']}(Protection: {measure['protection_level']}){self.colors['reset']}")
            
            return security_measures
            
        except Exception as e:
            self._print_status(f"Error checking security measures: {e}", 'error')
            return []

    def _detect_waf(self, url):
        """Try to detect Web Application Firewall"""
        try:
            headers = self._get_random_headers()
            response = self.session.get(url, headers=headers, timeout=self.config['timeout'])
            
            # Check common WAF headers
            waf_headers = ['X-Protected-By', 'X-WAF', 'Server', 'X-Security-System']
            for header in waf_headers:
                if header in response.headers:
                    return response.headers[header]
            
            # Check common WAF patterns in response
            if 'cloudflare' in response.headers.get('Server', '').lower():
                return 'Cloudflare'
            if 'akamai' in response.headers.get('Server', '').lower():
                return 'Akamai'
            if 'imperva' in response.headers.get('Server', '').lower():
                return 'Imperva'
            
            return None
        except:
            return None

    def _check_ssl(self, url):
        """Check SSL/TLS configuration"""
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return {'status': 'Not using HTTPS', 'protection_level': 'None'}
                
            context = ssl.create_default_context()
            with socket.create_connection((parsed_url.netloc, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=parsed_url.netloc) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check protocol version
                    if protocol == 'TLSv1.3':
                        return {'status': f'TLS 1.3 ({cipher[0]})', 'protection_level': 'High'}
                    elif protocol == 'TLSv1.2':
                        return {'status': f'TLS 1.2 ({cipher[0]})', 'protection_level': 'Medium'}
                    else:
                        return {'status': f'{protocol} ({cipher[0]}) - Outdated', 'protection_level': 'Low'}
        except Exception as e:
            return {'status': f'Error: {str(e)}', 'protection_level': 'Unknown'}

    def _check_rate_limiting(self, url):
        """Check if rate limiting is enabled"""
        try:
            # Make 5 quick requests to test rate limiting
            for _ in range(5):
                headers = self._get_random_headers()
                response = self.session.get(url, headers=headers, timeout=2)
                if response.status_code == 429:  # Too Many Requests
                    return True
            return False
        except:
            return False

    def full_stealth_scan(self, url, wordlist_path=None):
        """Perform comprehensive stealth scan of all aspects"""
        try:
            self.scan_results = {
                'target': url,
                'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'files': [],
                'paths': [],
                'vulnerabilities': {},
                'ports': [],
                'headers': {},
                'dns': {},
                'technologies': [],
                'sitemap': [],
                'emails': [],
                'comments': [],
                'hidden_params': [],
                'server_info': {},
                'security_measures': []
            }
            
            print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Starting Comprehensive Stealth Scan ════════{self.colors['reset']}")
            
            start_time = time.time()
            
            # Extract base domain
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # 1. Get server information
            self.get_server_info(url)
            
            # 2. Check security measures
            self.check_security_measures(url)
            
            # 3. DNS Reconnaissance
            self.scan_dns(domain)
            
            # 4. Port Scanning
            self.scan_ports(domain)
            
            # 5. HTTP Headers Check
            self.scan_http_headers(url)
            
            # 6. Technology Identification
            self.scan_technologies(url)
            
            # 7. Path Extraction
            self.scan_results['paths'] = self.extract_paths(url)
            
            # 8. Admin Page Discovery
            self.scan_results['admin_pages'] = self.scan_admin_pages(url)
            
            # 9. Sensitive File Scanning (if wordlist provided)
            if wordlist_path:
                self.scan_results['files'] = self.scan_sensitive_files(url, wordlist_path)
            
            # 10. Vulnerability Scanning
            self.scan_results['vulnerabilities'] = self.scan_vulnerabilities(url)
            
            # 11. Email and Comment Extraction
            email_results = self.extract_emails_comments(url)
            self.scan_results['emails'] = email_results['emails']
            self.scan_results['comments'] = email_results['comments']
            
            # Calculate scan duration
            elapsed_time = time.time() - start_time
            self.scan_results['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.scan_results['duration'] = f"{elapsed_time:.2f} seconds"
            
            # Save results
            self._save_results()
            
            # Print summary
            self._print_summary()
            
            return self.scan_results
            
        except Exception as e:
            self._print_status(f"Error during comprehensive scan: {e}", 'error')
            return None
    
    def _save_results(self, filename=None):
        """Save scan results to file"""
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"scan_results_{timestamp}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, ensure_ascii=False, indent=4)
            
            self._print_status(f"Scan results saved to: {filename}", 'success')
            return filename
            
        except Exception as e:
            self._print_status(f"Error saving results: {e}", 'error')
            return None
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{self.colors['yellow']}{self.colors['bold']}════════ Scan Summary ════════{self.colors['reset']}")
        print(f"{self.colors['cyan']}Target:{self.colors['reset']} {self.scan_results['target']}")
        print(f"{self.colors['cyan']}Start Time:{self.colors['reset']} {self.scan_results['start_time']}")
        print(f"{self.colors['cyan']}End Time:{self.colors['reset']} {self.scan_results['end_time']}")
        print(f"{self.colors['cyan']}Duration:{self.colors['reset']} {self.scan_results['duration']}")
        
        # Server info summary
        if self.scan_results.get('server_info'):
            print(f"\n{self.colors['cyan']}Server IP:{self.colors['reset']} {self.scan_results['server_info']['ip_address']}")
            print(f"{self.colors['cyan']}Hosting Provider:{self.colors['reset']} {self.scan_results['server_info']['hosting_provider']}")
        
        # Security measures summary
        if self.scan_results.get('security_measures'):
            high = sum(1 for m in self.scan_results['security_measures'] if m['protection_level'] == 'High')
            med = sum(1 for m in self.scan_results['security_measures'] if m['protection_level'] == 'Medium')
            low = sum(1 for m in self.scan_results['security_measures'] if m['protection_level'] == 'Low')
            print(f"{self.colors['cyan']}Security Level:{self.colors['reset']} {self.colors['green'] if high > med and high > low else self.colors['yellow'] if med > low else self.colors['red']}{high} High, {med} Medium, {low} Low{self.colors['reset']}")
        
        # Files summary
        if self.scan_results.get('files'):
            print(f"\n{self.colors['cyan']}Sensitive Files Found:{self.colors['reset']} {len(self.scan_results['files'])}")
        
        # Paths summary
        if self.scan_results.get('paths'):
            print(f"{self.colors['cyan']}Discovered Paths:{self.colors['reset']} {len(self.scan_results['paths'])}")
        
        # Admin pages summary
        if self.scan_results.get('admin_pages'):
            print(f"{self.colors['cyan']}Admin Pages Found:{self.colors['reset']} {len(self.scan_results['admin_pages'])}")
        
        # Vulnerabilities summary
        if self.scan_results.get('vulnerabilities'):
            vuln_count = sum(1 for vuln in self.scan_results['vulnerabilities'].values() if vuln['found'])
            print(f"{self.colors['cyan']}Vulnerabilities Found:{self.colors['reset']} {vuln_count}")
        
        # Ports summary
        if self.scan_results.get('ports'):
            print(f"{self.colors['cyan']}Open Ports:{self.colors['reset']} {len(self.scan_results['ports'])}")
        
        # Technologies summary
        if self.scan_results.get('technologies'):
            print(f"{self.colors['cyan']}Technologies Identified:{self.colors['reset']} {len(self.scan_results['technologies'])}")
        
        # Emails summary
        if self.scan_results.get('emails'):
            print(f"{self.colors['cyan']}Emails Extracted:{self.colors['reset']} {len(self.scan_results['emails'])}")
        
        print(f"\n{self.colors['green']}Scan completed successfully!{self.colors['reset']}")

def main():
    # Create scanner instance
    scanner = GoldenScanner()
    
    # Display the complete launch sequence
    scanner._show_launch_sequence()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Golden Web Vulnerability Scanner - Ultimate Edition V1.0')
    parser.add_argument('-u', '--url', help='Target website URL')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path')
    parser.add_argument('-o', '--output', help='Custom output file name')
    parser.add_argument('--stealth', action='store_true', help='Enable full stealth mode')
    parser.add_argument('--fast', action='store_true', help='Enable fast mode (no delays)')
    args = parser.parse_args()
    
    # Apply command line settings
    if args.stealth:
        scanner.config['stealth_mode'] = True
        scanner.config['max_threads'] = 3
        scanner.config['delay_range'] = (2, 5)
    if args.fast:
        scanner.config['stealth_mode'] = False
        scanner.config['max_threads'] = 10
        scanner.config['delay_range'] = (0, 0.5)
    
    # Request URL if not provided
    if not args.url:
        args.url = input(f"{scanner.colors['yellow']}Enter target website URL: {scanner.colors['reset']}")
    
    # Main menu loop
    while True:
        scanner._print_menu()
        choice = input(f"{scanner.colors['yellow']}Select option (0-11): {scanner.colors['reset']}")
        
        if choice == '0':
            scanner._print_status("Exiting...", 'success')
            sys.exit(0)
        elif choice == '1':
            wordlist_path = args.wordlist if args.wordlist else scanner._show_wordlist_menu()
            if wordlist_path:
                scanner.scan_sensitive_files(args.url, wordlist_path)
        elif choice == '2':
            scanner.scan_http_headers(args.url)
        elif choice == '3':
            scanner.scan_admin_pages(args.url)
        elif choice == '4':
            scanner.scan_vulnerabilities(args.url)
        elif choice == '5':
            domain = urlparse(args.url).netloc
            scanner.scan_ports(domain)
        elif choice == '6':
            scanner.extract_paths(args.url)
        elif choice == '7':
            scanner.scan_technologies(args.url)
        elif choice == '8':
            domain = urlparse(args.url).netloc
            scanner.scan_dns(domain)
        elif choice == '9':
            wordlist_path = args.wordlist if args.wordlist else scanner._show_wordlist_menu()
            if wordlist_path:
                scanner.full_stealth_scan(args.url, wordlist_path)
        elif choice == '10':
            scanner.extract_emails_comments(args.url)
        elif choice == '11':
            scanner.get_server_info(args.url)
            scanner.check_security_measures(args.url)
        else:
            scanner._print_status("Invalid selection! Please try again.", 'error')

if __name__ == "__main__":
    main()
    