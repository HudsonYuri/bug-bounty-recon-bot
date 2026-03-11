# bugbounty_bot.py
"""
Bug Bounty Bot - Ferramenta de Automação para Bug Bounty
Versão: 1.0.0
"""

import os
import sys
import json
import time
import socket
import logging
import argparse
import sqlite3
import requests
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor
import re

# ==================== CONFIGURAÇÃO ====================

@dataclass
class Config:
    """Configuração global do bot"""
    workspace_dir: str = "workspace"
    threads: int = 50
    timeout: int = 5
    rate_limit: float = 1.0
    use_proxy: bool = False
    proxy_list: List[str] = None
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    tools_path: str = "tools"
    verbose: bool = False
    debug: bool = False
    
@dataclass
class Target:
    """Representa um alvo no programa de bug bounty"""
    domain: str
    scope_inclusions: List[str] = field(default_factory=list)
    scope_exclusions: List[str] = field(default_factory=list)
    program_name: str = ""
    in_scope_subdomains: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    
@dataclass
class Asset:
    """Representa um ativo descoberto"""
    domain: str
    ip_addresses: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    technologies: Dict[str, str] = field(default_factory=dict)
    endpoints: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    status: str = "discovered"
    last_scan: str = ""
    
@dataclass
class Vulnerability:
    """Representa uma vulnerabilidade encontrada"""
    name: str
    severity: str
    asset: str
    endpoint: str
    description: str
    remediation: str
    cve: Optional[str] = None
    cvss: Optional[float] = None
    evidence: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())

# ==================== LOGGING ====================

def setup_logging(verbose: bool = False, debug: bool = False):
    """Configura o sistema de logging"""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('bugbounty_bot.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# ==================== MÓDULO 1: GERENCIADOR DE ALVOS ====================

class TargetManager:
    """Gerencia os alvos e escopos do programa de bug bounty"""
    
    def __init__(self, db_path: str = "targets.db"):
        self.logger = logging.getLogger(__name__)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_database()
        self.targets: Dict[str, Target] = {}
        self.load_targets()
        
    def _init_database(self):
        """Inicializa as tabelas do banco de dados"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                program_name TEXT,
                scope_inclusions TEXT,
                scope_exclusions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                domain TEXT,
                ip_addresses TEXT,
                ports TEXT,
                technologies TEXT,
                status TEXT,
                last_scan TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                name TEXT,
                severity TEXT,
                endpoint TEXT,
                description TEXT,
                remediation TEXT,
                cve TEXT,
                cvss REAL,
                evidence TEXT,
                discovered_at TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES assets (id)
            )
        ''')
        
        self.conn.commit()
        
    def add_target(self, domain: str, program_name: str = "", 
                   scope_inclusions: List[str] = None, 
                   scope_exclusions: List[str] = None):
        """Adiciona um novo alvo ao banco de dados"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO targets 
                (domain, program_name, scope_inclusions, scope_exclusions)
                VALUES (?, ?, ?, ?)
            ''', (
                domain, 
                program_name, 
                json.dumps(scope_inclusions or []),
                json.dumps(scope_exclusions or [])
            ))
            self.conn.commit()
            self.logger.info(f"Target {domain} added successfully")
            self.load_targets()
        except Exception as e:
            self.logger.error(f"Error adding target {domain}: {e}")
            
    def load_targets(self):
        """Carrega todos os alvos do banco de dados"""
        self.cursor.execute('SELECT * FROM targets')
        rows = self.cursor.fetchall()
        
        for row in rows:
            target = Target(
                domain=row[1],
                program_name=row[2],
                scope_inclusions=json.loads(row[3]) if row[3] else [],
                scope_exclusions=json.loads(row[4]) if row[4] else []
            )
            self.targets[row[1]] = target
            
    def is_in_scope(self, domain: str, subdomain: str) -> bool:
        """Verifica se um subdomínio está dentro do escopo"""
        target = self.targets.get(domain)
        if not target:
            return False
            
        for exclusion in target.scope_exclusions:
            if re.match(exclusion.replace('*', '.*'), subdomain):
                return False
                
        if not target.scope_inclusions:
            return True
            
        for inclusion in target.scope_inclusions:
            if re.match(inclusion.replace('*', '.*'), subdomain):
                return True
                
        return False
        
    def get_all_targets(self) -> List[str]:
        """Retorna todos os domínios alvo"""
        return list(self.targets.keys())
        
    def save_asset(self, target_domain: str, asset: Asset):
        """Salva um ativo no banco de dados"""
        target_id = self._get_target_id(target_domain)
        if not target_id:
            return
            
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO assets 
                (target_id, domain, ip_addresses, ports, technologies, status, last_scan)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                target_id,
                asset.domain,
                json.dumps(asset.ip_addresses),
                json.dumps(asset.ports),
                json.dumps(asset.technologies),
                asset.status,
                datetime.now().isoformat()
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error saving asset {asset.domain}: {e}")
            
    def save_vulnerability(self, asset_domain: str, vuln: Vulnerability):
        """Salva uma vulnerabilidade no banco de dados"""
        asset_id = self._get_asset_id(asset_domain)
        if not asset_id:
            return
            
        try:
            self.cursor.execute('''
                INSERT INTO vulnerabilities 
                (asset_id, name, severity, endpoint, description, remediation, 
                 cve, cvss, evidence, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                asset_id,
                vuln.name,
                vuln.severity,
                vuln.endpoint,
                vuln.description,
                vuln.remediation,
                vuln.cve,
                vuln.cvss,
                vuln.evidence,
                vuln.discovered_at
            ))
            self.conn.commit()
            self.logger.warning(f"Vulnerability found: {vuln.name} on {asset_domain}")
        except Exception as e:
            self.logger.error(f"Error saving vulnerability: {e}")
            
    def _get_target_id(self, domain: str) -> Optional[int]:
        self.cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
        result = self.cursor.fetchone()
        return result[0] if result else None
        
    def _get_asset_id(self, domain: str) -> Optional[int]:
        self.cursor.execute('SELECT id FROM assets WHERE domain = ?', (domain,))
        result = self.cursor.fetchone()
        return result[0] if result else None

# ==================== MÓDULO 2 & 3: DESCOBERTA DE ATIVOS E SUBDOMÍNIOS ====================

class AssetDiscovery:
    """Descobre subdomínios e ativos relacionados ao alvo"""
    
    def __init__(self, config: Config, target_manager: TargetManager):
        self.config = config
        self.target_manager = target_manager
        self.logger = logging.getLogger(__name__)
        self.found_subdomains: Set[str] = set()
        
    def run_passive_discovery(self, domain: str) -> Set[str]:
        """Executa descoberta passiva de subdomínios usando múltiplas fontes"""
        self.logger.info(f"Starting passive discovery for {domain}")
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [
                executor.submit(self._crtsh_search, domain),
                executor.submit(self._hackertarget_search, domain),
                executor.submit(self._securitytrails_search, domain),
                executor.submit(self._alienvault_search, domain),
                executor.submit(self._wayback_machine, domain),
                executor.submit(self._commoncrawl_search, domain),
                executor.submit(self._rapiddns_search, domain),
            ]
            
            for future in futures:
                try:
                    subdomains = future.result(timeout=30)
                    self.found_subdomains.update(subdomains)
                except Exception as e:
                    self.logger.debug(f"Error in passive source: {e}")
                    
        self.logger.info(f"Passive discovery found {len(self.found_subdomains)} subdomains")
        return self.found_subdomains
        
    def _crtsh_search(self, domain: str) -> Set[str]:
        """Busca subdomínios no crt.sh (certificados SSL)"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=self.config.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for sub in name.split('\n'):
                            if sub.endswith(domain) and '*' not in sub:
                                subdomains.add(sub.lower())
        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")
        return subdomains
        
    def _hackertarget_search(self, domain: str) -> Set[str]:
        """Busca subdomínios no HackerTarget"""
        subdomains = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=self.config.timeout)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line and ',' in line:
                        sub = line.split(',')[0]
                        if sub.endswith(domain):
                            subdomains.add(sub.lower())
        except Exception as e:
            self.logger.debug(f"HackerTarget error: {e}")
        return subdomains
        
    def _securitytrails_search(self, domain: str) -> Set[str]:
        """Busca subdomínios no SecurityTrails (requer API key)"""
        return set()
        
    def _alienvault_search(self, domain: str) -> Set[str]:
        """Busca subdomínios no AlienVault OTX"""
        subdomains = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            response = requests.get(url, timeout=self.config.timeout)
            if response.status_code == 200:
                data = response.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '')
                    if hostname and hostname.endswith(domain):
                        subdomains.add(hostname.lower())
        except Exception as e:
            self.logger.debug(f"AlienVault error: {e}")
        return subdomains
        
    def _wayback_machine(self, domain: str) -> Set[str]:
        """Busca subdomínios no Wayback Machine"""
        subdomains = set()
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=self.config.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:
                    if entry and len(entry) > 0:
                        url_str = entry[0]
                        parsed = urlparse(url_str)
                        hostname = parsed.netloc or parsed.path.split('/')[0]
                        if hostname and hostname.endswith(domain):
                            subdomains.add(hostname.lower())
        except Exception as e:
            self.logger.debug(f"Wayback Machine error: {e}")
        return subdomains
        
    def _commoncrawl_search(self, domain: str) -> Set[str]:
        """Busca subdomínios no Common Crawl"""
        subdomains = set()
        try:
            index_url = "https://index.commoncrawl.org/collinfo.json"
            response = requests.get(index_url, timeout=self.config.timeout)
            if response.status_code == 200:
                indexes = response.json()
                if indexes:
                    latest = indexes[0]['id']
                    search_url = f"https://index.commoncrawl.org/{latest}-cdx?url=*.{domain}&output=json"
                    response = requests.get(search_url, timeout=self.config.timeout)
                    if response.status_code == 200:
                        for line in response.text.split('\n'):
                            if line:
                                try:
                                    data = json.loads(line)
                                    url = data.get('url', '')
                                    hostname = urlparse(url).netloc
                                    if hostname and hostname.endswith(domain):
                                        subdomains.add(hostname.lower())
                                except:
                                    pass
        except Exception as e:
            self.logger.debug(f"Common Crawl error: {e}")
        return subdomains
        
    def _rapiddns_search(self, domain: str) -> Set[str]:
        """Busca subdomínios no RapidDNS"""
        subdomains = set()
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=self.config.timeout)
            if response.status_code == 200:
                pattern = rf'([a-zA-Z0-9][a-zA-Z0-9.-]*\.{re.escape(domain)})'
                matches = re.findall(pattern, response.text)
                subdomains.update(m.lower() for m in matches)
        except Exception as e:
            self.logger.debug(f"RapidDNS error: {e}")
        return subdomains
        
    def run_bruteforce_discovery(self, domain: str, wordlist: str = None) -> Set[str]:
        """Executa descoberta ativa via brute force de subdomínios"""
        self.logger.info(f"Starting bruteforce discovery for {domain}")
        
        if not wordlist:
            wordlist = os.path.join(self.config.tools_path, "wordlists", "subdomains.txt")
            
        if not os.path.exists(wordlist):
            self.logger.warning(f"Wordlist not found: {wordlist}")
            return set()
            
        subdomains = set()
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
                self.logger.debug(f"Found: {full_domain}")
            except:
                pass
                
        with open(wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
            
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            executor.map(check_subdomain, words)
            
        self.logger.info(f"Bruteforce found {len(subdomains)} subdomains")
        return subdomains

# ==================== MÓDULO 4: DETECÇÃO DE HOSTS ATIVOS ====================

class HostProber:
    """Verifica quais hosts estão ativos e respondendo"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.active_hosts: Set[str] = set()
        
    def probe_hosts(self, hosts: List[str]) -> Set[str]:
        """Verifica quais hosts estão ativos via HTTP/HTTPS"""
        self.logger.info(f"Probing {len(hosts)} hosts for activity")
        
        def check_host(host):
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{host}"
                    response = requests.get(
                        url, 
                        timeout=self.config.timeout,
                        allow_redirects=True,
                        verify=False
                    )
                    if response.status_code < 500:
                        self.active_hosts.add(host)
                        self.logger.debug(f"Active: {url} -> {response.status_code}")
                        return
                except:
                    pass
                    
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            executor.map(check_host, hosts)
            
        self.logger.info(f"Found {len(self.active_hosts)} active hosts")
        return self.active_hosts
        
    def get_response_details(self, host: str) -> Dict[str, Any]:
        """Obtém detalhes da resposta HTTP para um host"""
        details = {}
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{host}"
                response = requests.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=True,
                    verify=False
                )
                details = {
                    'url': url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'server': response.headers.get('Server', ''),
                    'content_type': response.headers.get('Content-Type', ''),
                    'content_length': len(response.content),
                    'title': self._extract_title(response.text)
                }
                break
            except:
                continue
        return details
        
    def _extract_title(self, html: str) -> str:
        """Extrai o título de uma página HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

# ==================== MÓDULO 5: ESCANEAMENTO DE PORTAS ====================

class PortScanner:
    """Escaneia portas abertas em hosts alvo"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465,
            587, 993, 995, 1080, 1433, 1434, 1521, 1723, 2082, 2083, 2086, 2087,
            2095, 2096, 3306, 3389, 3690, 5432, 5800, 5900, 5901, 5984, 5985,
            5986, 6379, 7001, 7002, 8000, 8001, 8008, 8009, 8080, 8081, 8083,
            8086, 8088, 8089, 8090, 8161, 8181, 8443, 8880, 8888, 9000, 9001,
            9043, 9060, 9080, 9090, 9091, 9100, 9200, 9300, 9443, 9999, 10000,
            11211, 27017, 27018, 28017, 50000, 50030, 50060, 50070
        ]
        
    def scan_ports(self, hosts: List[str], ports: List[int] = None) -> Dict[str, List[int]]:
        """Escaneia portas em múltiplos hosts"""
        self.logger.info(f"Scanning ports on {len(hosts)} hosts")
        
        if ports is None:
            ports = self.common_ports
            
        results = {}
        
        def scan_host(host):
            open_ports = []
            for port in ports:
                if self._check_port(host, port):
                    open_ports.append(port)
                    self.logger.debug(f"Port {port} open on {host}")
            if open_ports:
                results[host] = open_ports
                
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            executor.map(scan_host, hosts)
            
        self.logger.info(f"Found ports on {len(results)} hosts")
        return results
        
    def _check_port(self, host: str, port: int) -> bool:
        """Verifica se uma porta específica está aberta"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
        
    def scan_with_nmap(self, host: str) -> Dict[str, Any]:
        """Usa nmap para scan mais detalhado (requer nmap instalado)"""
        try:
            cmd = f"nmap -sV -sC -O -p- {host} -oN -"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_output(result.stdout)
        except Exception as e:
            self.logger.error(f"Nmap scan failed for {host}: {e}")
            return {}
            
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parseia saída do nmap (simplificado)"""
        results = {}
        
        for line in output.split('\n'):
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    if state == 'open':
                        port = int(port_proto.split('/')[0])
                        results[port] = {
                            'state': state,
                            'service': service,
                            'version': ' '.join(parts[3:]) if len(parts) > 3 else ""
                        }
                        
        return results

# ==================== MÓDULO 6: DESCOBERTA DE URLs E ENDPOINTS ====================

class URLDiscoverer:
    """Descobre URLs e endpoints em hosts alvo"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.common_paths = [
            'robots.txt', 'sitemap.xml', '.git/HEAD', '.env', 'wp-config.php',
            'admin', 'login', 'api', 'v1', 'v2', 'backup', 'backups', 'dump',
            'phpinfo.php', 'info.php', 'test.php', 'uploads', 'download',
            'files', 'images', 'css', 'js', 'assets', 'static', 'public',
            'swagger', 'docs', 'documentation', 'graphql', 'graphiql',
            'server-status', 'server-info', '.well-known/security.txt'
        ]
        
    def discover_urls(self, hosts: List[str], use_wayback: bool = True, 
                      use_common_paths: bool = True) -> Dict[str, Set[str]]:
        """Descobre URLs para cada host"""
        self.logger.info(f"Discovering URLs for {len(hosts)} hosts")
        
        results = {host: set() for host in hosts}
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            
            for host in hosts:
                if use_wayback:
                    futures.append(executor.submit(self._get_wayback_urls, host))
                    
            for future in futures:
                try:
                    host, urls = future.result(timeout=60)
                    results[host].update(urls)
                except Exception as e:
                    self.logger.debug(f"Error in URL discovery: {e}")
                    
        if use_common_paths:
            self._check_common_paths(hosts, results)
            
        total = sum(len(urls) for urls in results.values())
        self.logger.info(f"Discovered {total} URLs")
        
        return results
        
    def _get_wayback_urls(self, host: str) -> tuple:
        """Obtém URLs do Wayback Machine para um host"""
        urls = set()
        try:
            domain = host.split(':')[0]
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=self.config.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:
                    if entry and len(entry) > 0:
                        urls.add(entry[0])
        except Exception as e:
            self.logger.debug(f"Wayback error for {host}: {e}")
            
        return host, urls
        
    def _check_common_paths(self, hosts: List[str], results: Dict[str, Set[str]]):
        """Verifica paths comuns em cada host"""
        def check_paths(host):
            found_urls = set()
            for protocol in ['https', 'http']:
                base_url = f"{protocol}://{host}"
                for path in self.common_paths:
                    url = f"{base_url}/{path}"
                    try:
                        response = requests.get(
                            url, 
                            timeout=self.config.timeout,
                            allow_redirects=False,
                            verify=False
                        )
                        if response.status_code < 400 or response.status_code == 403:
                            found_urls.add(url)
                            self.logger.debug(f"Found: {url} -> {response.status_code}")
                    except:
                        pass
            return host, found_urls
            
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(check_paths, host) for host in hosts]
            for future in futures:
                try:
                    host, found_urls = future.result(timeout=30)
                    results[host].update(found_urls)
                except Exception as e:
                    self.logger.debug(f"Error checking common paths: {e}")

# ==================== MÓDULO 7: IDENTIFICAÇÃO DE TECNOLOGIAS ====================

class TechnologyIdentifier:
    """Identifica tecnologias usadas pelos hosts"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.fingerprints = {
            'server': {
                'nginx': ['nginx'],
                'apache': ['apache'],
                'iis': ['microsoft-iis', 'iis'],
                'cloudflare': ['cloudflare'],
                'aws': ['aws', 'amazon'],
                'gunicorn': ['gunicorn']
            },
            'headers': {
                'x-powered-by': ['php', 'asp.net', 'express'],
                'x-aspnet-version': ['asp.net'],
                'x-drupal-cache': ['drupal'],
                'x-generator': ['wordpress', 'drupal', 'joomla'],
                'x-drupal-dynamic-cache': ['drupal'],
                'x-varnish': ['varnish'],
                'via': ['varnish', 'cloudflare', 'akamai']
            },
            'cookies': {
                'PHPSESSID': ['php'],
                'JSESSIONID': ['java'],
                'ASP.NET_SessionId': ['asp.net'],
                'wp-settings': ['wordpress']
            },
            'html': {
                'wp-content': ['wordpress'],
                'wp-includes': ['wordpress'],
                'drupal': ['drupal'],
                'joomla': ['joomla'],
                'csrf-token': ['laravel'],
                'livewire': ['laravel livewire']
            }
        }
        
    def identify(self, hosts: List[str]) -> Dict[str, Dict[str, str]]:
        """Identifica tecnologias para cada host"""
        self.logger.info(f"Identifying technologies for {len(hosts)} hosts")
        
        results = {}
        
        def identify_host(host):
            tech = {}
            
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{host}"
                    response = requests.get(
                        url,
                        timeout=self.config.timeout,
                        allow_redirects=True,
                        verify=False
                    )
                    
                    server = response.headers.get('Server', '')
                    if server:
                        tech['server'] = server
                        
                    for header, patterns in self.fingerprints['headers'].items():
                        value = response.headers.get(header, '').lower()
                        for pattern in patterns:
                            if pattern in value:
                                tech[header] = value
                                
                    for cookie_name, patterns in self.fingerprints['cookies'].items():
                        if cookie_name in response.cookies:
                            for pattern in patterns:
                                tech[f'cookie_{cookie_name}'] = pattern
                                
                    if 'text/html' in response.headers.get('Content-Type', ''):
                        html = response.text.lower()
                        for html_pattern, patterns in self.fingerprints['html'].items():
                            if html_pattern in html:
                                for pattern in patterns:
                                    tech[f'html_{html_pattern}'] = pattern
                                    
                    if 'script' in html:
                        if 'react' in html or 'reactdom' in html:
                            tech['js_framework'] = 'react'
                        elif 'vue' in html:
                            tech['js_framework'] = 'vue'
                        elif 'angular' in html:
                            tech['js_framework'] = 'angular'
                            
                    if 'cf-ray' in response.headers:
                        tech['cloudflare'] = 'enabled'
                        
                    if 'x-amz-cf-id' in response.headers:
                        tech['aws'] = 'cloudfront'
                        
                    break
                    
                except Exception as e:
                    continue
                    
            return host, tech
            
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(identify_host, host) for host in hosts]
            for future in futures:
                try:
                    host, tech = future.result(timeout=30)
                    if tech:
                        results[host] = tech
                        self.logger.debug(f"Technologies for {host}: {tech}")
                except Exception as e:
                    self.logger.debug(f"Error identifying technologies: {e}")
                    
        self.logger.info(f"Identified technologies for {len(results)} hosts")
        return results

# ==================== MÓDULO 8: ESCANEAMENTO DE VULNERABILIDADES ====================

class VulnerabilityScanner:
    """Escaneia vulnerabilidades conhecidas usando Nuclei e verificações customizadas"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[Vulnerability] = []
        
    def scan_with_nuclei(self, targets: List[str]) -> List[Dict]:
        """Usa Nuclei para escanear vulnerabilidades"""
        self.logger.info(f"Starting Nuclei scan on {len(targets)} targets")
        
        results = []
        
        with open('/tmp/nuclei_targets.txt', 'w') as f:
            f.write('\n'.join(targets))
            
        try:
            cmd = f"nuclei -l /tmp/nuclei_targets.txt -json -o /tmp/nuclei_results.json"
            subprocess.run(cmd, shell=True, timeout=600)
            
            if os.path.exists('/tmp/nuclei_results.json'):
                with open('/tmp/nuclei_results.json', 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line)
                            results.append(result)
                        except:
                            continue
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            
        for f in ['/tmp/nuclei_targets.txt', '/tmp/nuclei_results.json']:
            if os.path.exists(f):
                os.remove(f)
                
        self.logger.info(f"Nuclei found {len(results)} potential issues")
        return results
        
    def check_misconfigurations(self, hosts: List[str], urls: Dict[str, Set[str]]) -> List[Vulnerability]:
        """Verifica configurações incorretas comuns"""
        self.logger.info("Checking for common misconfigurations")
        
        vulns = []
        
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection'
        ]
        
        for host in hosts:
            try:
                url = f"https://{host}"
                response = requests.get(url, timeout=self.config.timeout, verify=False)
                
                missing_headers = []
                for header in security_headers:
                    if header not in response.headers:
                        missing_headers.append(header)
                        
                if missing_headers:
                    vuln = Vulnerability(
                        name="Missing Security Headers",
                        severity="medium",
                        asset=host,
                        endpoint=url,
                        description=f"Missing security headers: {', '.join(missing_headers)}",
                        remediation="Implement recommended security headers"
                    )
                    vulns.append(vuln)
                    
            except Exception as e:
                self.logger.debug(f"Error checking headers for {host}: {e}")
                
        sensitive_patterns = [
            (r'\.git/config', 'critical', 'Git Config Exposed'),
            (r'\.env', 'critical', 'Environment File Exposed'),
            (r'wp-config\.php', 'high', 'WordPress Config Exposed'),
            (r'config\.php', 'high', 'PHP Config Exposed'),
            (r'\.aws/credentials', 'critical', 'AWS Credentials Exposed'),
            (r'id_rsa', 'critical', 'Private SSH Key Exposed'),
            (r'\.htaccess', 'medium', 'HTAccess File Exposed'),
            (r'\.svn/entries', 'high', 'SVN Entries Exposed'),
            (r'phpinfo\.php', 'medium', 'PHPInfo Exposed'),
            (r'info\.php', 'medium', 'PHPInfo Exposed'),
            (r'backup\.zip', 'high', 'Backup File Exposed'),
            (r'backup\.tar\.gz', 'high', 'Backup File Exposed'),
        ]
        
        for host, host_urls in urls.items():
            for url in host_urls:
                for pattern, severity, name in sensitive_patterns:
                    if re.search(pattern, url):
                        vuln = Vulnerability(
                            name=name,
                            severity=severity,
                            asset=host,
                            endpoint=url,
                            description=f"Sensitive file exposed at {url}",
                            remediation="Remove or restrict access to sensitive files",
                            evidence=f"URL accessible: {url}"
                        )
                        vulns.append(vuln)
                        break
                        
        self.logger.info(f"Found {len(vulns)} misconfigurations")
        return vulns
        
    def check_cves(self, technologies: Dict[str, Dict[str, str]]) -> List[Vulnerability]:
        """Verifica CVEs conhecidas baseado nas tecnologias identificadas"""
        return []

# ==================== MÓDULO 9 & 10: CORRELAÇÃO E PRIORIZAÇÃO ====================

class DataCorrelator:
    """Correlaciona dados de diferentes fontes e prioriza vulnerabilidades"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def correlate(self, assets: List[Asset], vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Correlaciona todos os dados coletados"""
        self.logger.info("Correlating collected data")
        
        correlation = {
            'summary': {
                'total_assets': len(assets),
                'total_vulnerabilities': len(vulnerabilities),
                'assets_with_vulns': 0,
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            },
            'assets': {},
            'top_risks': []
        }
        
        vulns_by_asset = {}
        for vuln in vulnerabilities:
            if vuln.asset not in vulns_by_asset:
                vulns_by_asset[vuln.asset] = []
            vulns_by_asset[vuln.asset].append(vuln)
            correlation['summary']['severity_counts'][vuln.severity] += 1
            
        for asset in assets:
            asset_vulns = vulns_by_asset.get(asset.domain, [])
            
            if asset_vulns:
                correlation['summary']['assets_with_vulns'] += 1
                
            risk_score = self._calculate_risk_score(asset_vulns)
            
            correlation['assets'][asset.domain] = {
                'ip_addresses': asset.ip_addresses,
                'ports': asset.ports,
                'technologies': asset.technologies,
                'endpoints': asset.endpoints[:10],
                'vulnerabilities': [asdict(v) for v in asset_vulns],
                'vulnerability_count': len(asset_vulns),
                'risk_score': risk_score,
                'risk_level': self._get_risk_level(risk_score)
            }
            
        for asset_name, asset_data in correlation['assets'].items():
            if asset_data['vulnerabilities']:
                correlation['top_risks'].append({
                    'asset': asset_name,
                    'risk_score': asset_data['risk_score'],
                    'risk_level': asset_data['risk_level'],
                    'critical_vulns': sum(1 for v in asset_data['vulnerabilities'] if v['severity'] == 'critical'),
                    'high_vulns': sum(1 for v in asset_data['vulnerabilities'] if v['severity'] == 'high')
                })
                
        correlation['top_risks'].sort(key=lambda x: x['risk_score'], reverse=True)
        
        return correlation
        
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calcula score de risco baseado nas vulnerabilidades"""
        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.5
        }
        
        if not vulnerabilities:
            return 0.0
            
        total_weight = sum(severity_weights.get(v.severity, 0) for v in vulnerabilities)
        score = min(10.0, total_weight / len(vulnerabilities) * 2)
        
        return round(score, 1)
        
    def _get_risk_level(self, score: float) -> str:
        """Converte score numérico para nível de risco"""
        if score >= 8.0:
            return 'CRITICAL'
        elif score >= 6.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score >= 2.0:
            return 'LOW'
        else:
            return 'INFO'

# ==================== MÓDULO 11: GERADOR DE RELATÓRIOS ====================

class ReportGenerator:
    """Gera relatórios em diferentes formatos"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
    def generate_html(self, correlation_data: Dict[str, Any], target_domain: str) -> str:
        """Gera relatório HTML"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"report_{target_domain}_{timestamp}.html"
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Bug Bounty Report - {target_domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ background: #e8f4f8; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .stat {{ display: inline-block; margin-right: 30px; }}
                .stat-value {{ font-size: 24px; font-weight: bold; }}
                .stat-label {{ color: #666; }}
                .risk-critical {{ color: #dc3545; font-weight: bold; }}
                .risk-high {{ color: #fd7e14; font-weight: bold; }}
                .risk-medium {{ color: #ffc107; font-weight: bold; }}
                .risk-low {{ color: #28a745; font-weight: bold; }}
                .risk-info {{ color: #17a2b8; font-weight: bold; }}
                table {{ width: 100%%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f2f2f2; }}
                tr:hover {{ background: #f5f5f5; }}
                .vuln-details {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .timestamp {{ color: #666; font-size: 12px; margin-top: 20px; text-align: right; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Bug Bounty Scan Report</h1>
                <p>Target: <strong>{target_domain}</strong></p>
                <p>Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong></p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <div class="stat">
                        <div class="stat-value">{correlation_data['summary']['total_assets']}</div>
                        <div class="stat-label">Total Assets</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{correlation_data['summary']['assets_with_vulns']}</div>
                        <div class="stat-label">Assets with Vulns</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{correlation_data['summary']['total_vulnerabilities']}</div>
                        <div class="stat-label">Total Vulns</div>
                    </div>
                    <div style="margin-top: 15px;">
                        <span class="risk-critical">Critical: {correlation_data['summary']['severity_counts']['critical']}</span> | 
                        <span class="risk-high">High: {correlation_data['summary']['severity_counts']['high']}</span> | 
                        <span class="risk-medium">Medium: {correlation_data['summary']['severity_counts']['medium']}</span> | 
                        <span class="risk-low">Low: {correlation_data['summary']['severity_counts']['low']}</span> | 
                        <span class="risk-info">Info: {correlation_data['summary']['severity_counts']['info']}</span>
                    </div>
                </div>
                
                <h2>Top Risks</h2>
                <table>
                    <tr>
                        <th>Asset</th>
                        <th>Risk Level</th>
                        <th>Risk Score</th>
                        <th>Critical</th>
                        <th>High</th>
                    </tr>
        """
        
        for risk in correlation_data['top_risks'][:10]:
            risk_class = f"risk-{risk['risk_level'].lower()}"
            html_template += f"""
                    <tr>
                        <td>{risk['asset']}</td>
                        <td class="{risk_class}">{risk['risk_level']}</td>
                        <td>{risk['risk_score']}</td>
                        <td>{risk['critical_vulns']}</td>
                        <td>{risk['high_vulns']}</td>
                    </tr>
            """
            
        html_template += """
                </table>
                
                <h2>Detailed Findings</h2>
        """
        
        for asset_name, asset_data in correlation_data['assets'].items():
            if asset_data['vulnerabilities']:
                html_template += f"""
                <div style="margin-top: 30px;">
                    <h3>{asset_name}</h3>
                    <p>IPs: {', '.join(asset_data['ip_addresses'])}</p>
                    <p>Ports: {', '.join(map(str, asset_data['ports']))}</p>
                    <p>Technologies: {', '.join(f"{k}: {v}" for k,v in asset_data['technologies'].items())}</p>
                    
                    <h4>Vulnerabilities ({asset_data['vulnerability_count']})</h4>
                """
                
                for vuln in asset_data['vulnerabilities']:
                    vuln_class = f"risk-{vuln['severity']}"
                    html_template += f"""
                    <div class="vuln-details">
                        <strong class="{vuln_class}">{vuln['severity'].upper()}</strong> - {vuln['name']}<br>
                        <strong>Endpoint:</strong> {vuln['endpoint']}<br>
                        <strong>Description:</strong> {vuln['description']}<br>
                        <strong>Remediation:</strong> {vuln['remediation']}<br>
                    </div>
                    """
                    
                html_template += "</div>"
                
        html_template += """
                <div class="timestamp">
                    Report generated by Bug Bounty Bot
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_template)
            
        self.logger.info(f"HTML report generated: {filename}")
        return str(filename)
        
    def generate_json(self, correlation_data: Dict[str, Any], target_domain: str) -> str:
        """Gera relatório JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"report_{target_domain}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(correlation_data, f, indent=2, default=str)
            
        self.logger.info(f"JSON report generated: {filename}")
        return str(filename)
        
    def generate_markdown(self, correlation_data: Dict[str, Any], target_domain: str) -> str:
        """Gera relatório Markdown"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"report_{target_domain}_{timestamp}.md"
        
        md = f"""# Bug Bounty Scan Report - {target_domain}

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary

| Metric | Value |
|--------|-------|
| Total Assets | {correlation_data['summary']['total_assets']} |
| Assets with Vulnerabilities | {correlation_data['summary']['assets_with_vulns']} |
| Total Vulnerabilities | {correlation_data['summary']['total_vulnerabilities']} |

### Severity Breakdown

- **Critical:** {correlation_data['summary']['severity_counts']['critical']}
- **High:** {correlation_data['summary']['severity_counts']['high']}
- **Medium:** {correlation_data['summary']['severity_counts']['medium']}
- **Low:** {correlation_data['summary']['severity_counts']['low']}
- **Info:** {correlation_data['summary']['severity_counts']['info']}

## Top Risks

| Asset | Risk Level | Score | Critical | High |
|-------|------------|-------|----------|------|
"""
        for risk in correlation_data['top_risks'][:10]:
            md += f"| {risk['asset']} | {risk['risk_level']} | {risk['risk_score']} | {risk['critical_vulns']} | {risk['high_vulns']} |\n"
            
        md += "\n## Detailed Findings\n"
        
        for asset_name, asset_data in correlation_data['assets'].items():
            if asset_data['vulnerabilities']:
                md += f"""
### {asset_name}

**IPs:** {', '.join(asset_data['ip_addresses'])}
**Ports:** {', '.join(map(str, asset_data['ports']))}
**Technologies:** {', '.join(f"{k}: {v}" for k,v in asset_data['technologies'].items())}

#### Vulnerabilities ({asset_data['vulnerability_count']})
"""
                for vuln in asset_data['vulnerabilities']:
                    md += f"""
* **{vuln['severity'].upper()}** - {vuln['name']}
  * Endpoint: {vuln['endpoint']}
  * Description: {vuln['description']}
  * Remediation: {vuln['remediation']}
"""
                    
        with open(filename, 'w') as f:
            f.write(md)
            
        self.logger.info(f"Markdown report generated: {filename}")
        return str(filename)

# ==================== BOT PRINCIPAL ====================

class BugBountyBot:
    """Orquestrador principal do Bug Bounty Bot"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logging(config.verbose, config.debug)
        
        self.target_manager = TargetManager()
        self.asset_discovery = AssetDiscovery(config, self.target_manager)
        self.host_prober = HostProber(config)
        self.port_scanner = PortScanner(config)
        self.url_discoverer = URLDiscoverer(config)
        self.tech_identifier = TechnologyIdentifier(config)
        self.vuln_scanner = VulnerabilityScanner(config)
        self.data_correlator = DataCorrelator()
        self.report_generator = ReportGenerator()
        
        self.workspace = Path(config.workspace_dir)
        self.workspace.mkdir(parents=True, exist_ok=True)
        
        self.logger.info("Bug Bounty Bot initialized successfully")
        
    def run(self, target_domain: str, program_name: str = ""):
        """Executa o pipeline completo para um alvo"""
        start_time = time.time()
        self.logger.info(f"Starting scan for target: {target_domain}")
        
        self.target_manager.add_target(target_domain, program_name)
        
        self.logger.info("[Phase 1] Starting asset discovery...")
        subdomains = self.asset_discovery.run_passive_discovery(target_domain)
        
        in_scope_subdomains = [
            sub for sub in subdomains 
            if self.target_manager.is_in_scope(target_domain, sub)
        ]
        
        self.logger.info(f"Found {len(in_scope_subdomains)} in-scope subdomains")
        
        with open(self.workspace / f"{target_domain}_subdomains.txt", 'w') as f:
            f.write('\n'.join(in_scope_subdomains))
            
        self.logger.info("[Phase 2] Probing for active hosts...")
        active_hosts = self.host_prober.probe_hosts(in_scope_subdomains)
        
        with open(self.workspace / f"{target_domain}_active.txt", 'w') as f:
            f.write('\n'.join(active_hosts))
            
        self.logger.info("[Phase 3] Scanning for open ports...")
        port_results = self.port_scanner.scan_ports(list(active_hosts))
        
        self.logger.info("[Phase 4] Discovering URLs and endpoints...")
        urls_by_host = self.url_discoverer.discover_urls(list(active_hosts))
        
        self.logger.info("[Phase 5] Identifying technologies...")
        technologies = self.tech_identifier.identify(list(active_hosts))
        
        assets = []
        for host in active_hosts:
            asset = Asset(
                domain=host,
                ip_addresses=[],
                ports=port_results.get(host, []),
                technologies=technologies.get(host, {}),
                endpoints=list(urls_by_host.get(host, set())),
                last_scan=datetime.now().isoformat()
            )
            assets.append(asset)
            self.target_manager.save_asset(target_domain, asset)
            
        self.logger.info("[Phase 6] Scanning for vulnerabilities...")
        
        nuclei_results = self.vuln_scanner.scan_with_nuclei(list(active_hosts))
        misconfig_vulns = self.vuln_scanner.check_misconfigurations(
            list(active_hosts), urls_by_host
        )
        
        nuclei_vulns = []
        for result in nuclei_results:
            vuln = Vulnerability(
                name=result.get('info', {}).get('name', 'Unknown'),
                severity=result.get('info', {}).get('severity', 'info'),
                asset=result.get('host', ''),
                endpoint=result.get('matched', ''),
                description=result.get('info', {}).get('description', ''),
                remediation=result.get('info', {}).get('remediation', ''),
                evidence=json.dumps(result)
            )
            nuclei_vulns.append(vuln)
            self.target_manager.save_vulnerability(vuln.asset, vuln)
            
        all_vulns = misconfig_vulns + nuclei_vulns
        
        self.logger.info("[Phase 7] Correlating data...")
        correlation = self.data_correlator.correlate(assets, all_vulns)
        
        self.logger.info("[Phase 8] Generating reports...")
        html_report = self.report_generator.generate_html(correlation, target_domain)
        json_report = self.report_generator.generate_json(correlation, target_domain)
        md_report = self.report_generator.generate_markdown(correlation, target_domain)
        
        elapsed_time = time.time() - start_time
        self.logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
        self.logger.info(f"Reports saved to: {html_report}, {json_report}, {md_report}")
        
        return correlation

# ==================== INTERFACE DE LINHA DE COMANDO ====================

def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Bot - Automated Reconnaissance Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-p', '--program', help='Bug bounty program name')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-o', '--output', default='workspace', help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--no-bruteforce', action='store_true', help='Skip bruteforce discovery')
    
    args = parser.parse_args()
    
    config = Config(
        workspace_dir=args.output,
        threads=args.threads,
        verbose=args.verbose,
        debug=args.debug
    )
    
    bot = BugBountyBot(config)
    
    try:
        results = bot.run(args.domain, args.program)
        print(f"\nScan completed successfully!")
        print(f"Summary: {results['summary']['total_assets']} assets, {results['summary']['total_vulnerabilities']} vulnerabilities")
        print(f"Reports saved in: {args.output}/reports/")
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
