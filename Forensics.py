import sqlite3
import os
import pandas as pd
import hashlib
import time
import logging
import re
import random
import json
from datetime import datetime
from textblob import TextBlob
import requests

# Logging setup
if not os.path.exists('logs'): os.makedirs('logs')
logging.basicConfig(filename='logs/forensics.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

DB_FILE = "fenix.db"
CONFIG_FILE = "config/forensics_config.json"

class ForensicProcessor:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._load_config()
        self.init_db()
        
    def _load_config(self):
        """Loads forensics config or sets defaults."""
        self.config = {
            'toxic_keywords': ['casino', 'apuestas', 'bet', 'porn', 'sex', 'viagra', 'cryptocurrency', 'bitmex'],
            'toxic_threshold': 70,
            'suspicious_threshold': 30
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
            except Exception as e:
                logging.error(f"Error loading config: {e}")

    def init_db(self):
        """Initializes the forensic database schema."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Domains table
        c.execute('''CREATE TABLE IF NOT EXISTS domains (
            domain TEXT PRIMARY KEY,
            authority_score INTEGER DEFAULT 0,
            status TEXT DEFAULT 'unknown',
            is_whitelisted INTEGER DEFAULT 0,
            last_seen TEXT
        )''')
        
        # Backlinks table
        c.execute('''CREATE TABLE IF NOT EXISTS backlinks (
            id TEXT PRIMARY KEY,
            url TEXT,
            target_url TEXT,
            domain TEXT,
            kri_score INTEGER DEFAULT 0,
            status_code INTEGER,
            content_hash TEXT,
            language TEXT,
            spam_density REAL,
            context_excerpt TEXT,
            created_at TEXT,
            kri_reasons TEXT,
            FOREIGN KEY(domain) REFERENCES domains(domain)
        )''')
        
        # Add kri_reasons column if not exists (migration)
        try:
            c.execute("ALTER TABLE backlinks ADD COLUMN kri_reasons TEXT")
        except sqlite3.OperationalError:
            pass # Column already exists
            
        # Scans table
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            filename TEXT,
            total_links INTEGER,
            processed_links INTEGER,
            started_at TEXT,
            finished_at TEXT,
            status TEXT
        )''')
        
        conn.commit()
        conn.close()
        logging.info("Database initialized successfully.")

    def read_gsc_csv(self, file_path):
        """
        Reads a Google Search Console CSV, handling BOM and dynamic column names.
        """
        try:
            # Detect encoding and read
            # GSC often uses UTF-16 or UTF-8 with BOM
            try:
                df = pd.read_csv(file_path, encoding='utf-16')
            except:
                df = pd.read_csv(file_path, encoding='utf-8-sig') # Handles BOM
                
            if df.empty:
                return None
                
            # Dynamic mapping
            col_map = {
                'url': next((c for c in df.columns if 'URL' in c.upper() or 'PÁGINA' in c.upper() or 'LINK' == c.lower()), None),
                'links': next((c for c in df.columns if 'LINK' in c.upper() or 'ENLACE' in c.upper()), None),
                'target': next((c for c in df.columns if 'TARGET' in c.upper() or 'DESTINO' in c.upper() or 'ENTIDAD' == c.upper()), None)
            }
            
            logging.info(f"Read CSV {file_path}. Columns mapped: {col_map}")
            return df, col_map
        except Exception as e:
            logging.error(f"Error reading CSV {file_path}: {e}")
            return None, None

    def is_whitelisted(self, domain):
        """Basic whitelisting for .edu and .gob domains."""
        if domain.endswith(('.edu', '.edu.mx', '.gob', '.gob.mx', '.gov')):
            return True
        # Add more logic or list comparison here
        return False

    def get_domain(self, url):
        """Extracts domain from a URL."""
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return "unknown"

    def calculate_authority_score(self, domain):
        """
        Estimates Domain Authority (DA) based on TLD and keywords.
        Heuristic approach since we don't have paid SEO APIs.
        """
        score = 30 # Base score for generic .com/.net
        
        # 1. TLD Bonus
        if domain.endswith(('.gov', '.gob.mx', '.mil')):
            score = 90
        elif domain.endswith(('.edu', '.edu.mx', '.ac.uk')):
            score = 80
        elif domain.endswith('.org'):
            score = 60
        elif domain.endswith(('.info', '.xyz', '.top', '.site', '.biz')):
            score = 10
            
        # 2. Name Penalty (Spammy keywords)
        if any(x in domain.lower() for x in ['casino', 'viagra', 'free', 'crypto', 'loan']):
            score = max(0, score - 20)
            
        return score

    def process_scan(self, file_path):
        """Standard workflow for a GSC scan."""
        df, mapping = self.read_gsc_csv(file_path)
        if df is None or not mapping['url']:
            return "Invalid file format or missing URL column."
            
        scan_id = f"scn_{int(time.time())}"
        self._add_scan_record(scan_id, os.path.basename(file_path), len(df))
        
        results = []
        for index, row in df.iterrows():
            url = row[mapping['url']]
            target = row[mapping['target']] if mapping['target'] else "MiMarca"
            
            res = self.process_link(url, target, scan_id)
            results.append(res)
            
            # Simple delay to be polite
            time.sleep(0.5) 
            
            # Update progress (could be used for websockets later)
            self._update_scan_progress(scan_id, index + 1)
            
        self._set_scan_finished(scan_id)
        return scan_id

    def process_link(self, url, target, scan_id):
        """Scrapes and analyzes a single link."""
        domain = self.get_domain(url)
        if self.is_whitelisted(domain):
            return {"url": url, "status": "whitelisted", "risk": 0}
            
        logging.info(f"Processing URL: {url}")
        
        # 1. Scrape Pasivo
        data = self._scrape_passive(url)
        
        # 1.5 Authority Score (Heuristic)
        authority_score = self.calculate_authority_score(domain)

        # 1.6 Context Sentiment
        sentiment_score, sentiment_label = self.analyze_context_sentiment(data['text'])
        
        # 2. Analyze Risk
        kri_score, status, kri_reasons = self.analyze_risk(data, url, domain)
        
        # 3. Persistence
        link_id = hashlib.md5(f"{url}_{scan_id}".encode()).hexdigest()
        self._save_backlink(link_id, url, target, domain, kri_score, data, scan_id, authority_score, sentiment_label, kri_reasons)
        
        return {"url": url, "risk": kri_score, "status": status, "authority": authority_score, "sentiment": sentiment_label, "reasons": kri_reasons}

    def check_link_liveness(self, url):
        """Active check if link is alive (200 OK)."""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Compatible; BrandSentinelBot/1.0)'}
            r = requests.head(url, headers=headers, timeout=10, verify=False)
            if r.status_code == 405: # Method Not Allowed
                r = requests.get(url, headers=headers, timeout=10, stream=True, verify=False)
            return r.status_code
        except Exception as e:
            logging.debug(f"Error checking link liveness {url}: {e}")
            return 0

    def analyze_context_sentiment(self, text):
        """Analyzes sentiment of the surrounding text."""
        if not text: return 0, "Neutro"
        try:
            analysis = TextBlob(text)
            pol = analysis.sentiment.polarity
            if pol > 0.1: return pol, "Positivo"
            if pol < -0.1: return pol, "Negativo"
            return pol, "Neutro"
        except Exception as e:
            logging.debug(f"Error checking link liveness {url}: {e}")
            return 0, "Neutro"

    def _scrape_passive(self, url):
        """Simple downloader with rotating User-Agents."""
        import requests
        from bs4 import BeautifulSoup
        
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        ]
        
        try:
            headers = {'User-Agent': random.choice(uas)}
            r = requests.get(url, headers=headers, timeout=15, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            return {
                'status_code': r.status_code,
                'text': soup.get_text()[:5000], # First 5k chars
                'lang': soup.find('html').get('lang') if soup.find('html') else 'unknown',
                'raw_html': r.text
            }
        except Exception as e:
            logging.error(f"Scrape failed for {url}: {e}")
            return {'status_code': 0, 'text': '', 'lang': 'error'}

    def analyze_risk(self, data, url, domain):
        """KRI Score v1 Calculation."""
        score = 0
        status = "Neutral"
        reasons = []
        
        if data['status_code'] == 0:
            return 80, "Malicious/Down", ["Fallo de conexión o Dominio Inexistente (+80)"] # Error or blocked usually means suspicious in forensic context
            
        # 1. Status Code Risk
        if data['status_code'] >= 400: 
            score += 20
            reasons.append(f"Estado HTTP {data['status_code']} sospechoso (+20)")
        
        # 2. Keywords Risk (Toxicity)
        toxic_keywords = self.config.get('toxic_keywords', []) # Modified
        found_toxic = [kw for kw in toxic_keywords if kw in data['text'].lower()]
        penalty = len(found_toxic) * 15
        if penalty > 0:
            score += penalty
            reasons.append(f"Palabras tóxicas ({len(found_toxic)}): {', '.join(found_toxic[:3])} (+{penalty})")
        
        # 3. Domain checks
        bad_tlds = ['-free.', '.top', '.xyz', '.online', '.site']
        matched_tld = [bad for bad in bad_tlds if bad in domain]
        if matched_tld:
            score += 10
            reasons.append(f"Dominio de baja reputación: {matched_tld[0]} (+10)")
            
        # Cap at 100
        score = min(score, 100)
        
        toxic_limit = self.config.get('toxic_threshold', 70) # Added
        suspicious_limit = self.config.get('suspicious_threshold', 30) # Added

        if score >= toxic_limit: status = "Toxic" # Modified
        elif score >= suspicious_limit: status = "Suspicious" # Modified
        elif score == 0: reasons.append("Sin indicadores de riesgo negativos")
        
        return score, status, reasons

    def _add_scan_record(self, scan_id, filename, total):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO scans (id, filename, total_links, processed_links, started_at, status) VALUES (?,?,?,?,?,?)",
                  (scan_id, filename, total, 0, datetime.now().isoformat(), 'running'))
        conn.commit()
        conn.close()

    def _update_scan_progress(self, scan_id, count):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE scans SET processed_links=? WHERE id=?", (count, scan_id))
        conn.commit()
        conn.close()

    def _set_scan_finished(self, scan_id):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE scans SET finished_at=?, status=? WHERE id=?", (datetime.now().isoformat(), 'completed', scan_id))
        conn.commit()
        conn.close()

    def _save_backlink(self, id, url, target, domain, score, data, scan_id, auth_score=0, sentiment="Neutro", kri_reasons=[]):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Update domain seen
        c.execute("INSERT OR IGNORE INTO domains (domain, last_seen, authority_score) VALUES (?,?,?)", (domain, datetime.now().isoformat(), auth_score))
        c.execute("UPDATE domains SET last_seen=?, authority_score=? WHERE domain=?", (datetime.now().isoformat(), auth_score, domain))
        
        # Save backlink (ensure columns exist, might need migration if schema changed)
        # For now we use context_excerpt to store sentiment label temporarily like "Sentiment: Positive | Excerpt..."
        context_data = f"Sentiment: {sentiment} | " + (data['text'][:100] if data['text'] else "")
        reasons_json = json.dumps(kri_reasons)

        c.execute("""INSERT OR REPLACE INTO backlinks 
                  (id, url, target_url, domain, kri_score, status_code, language, created_at, context_excerpt, kri_reasons) 
                  VALUES (?,?,?,?,?,?,?,?,?,?)""",
                  (id, url, target, domain, score, data['status_code'], data['lang'], datetime.now().isoformat(), context_data, reasons_json))
        conn.commit()
        conn.close()
