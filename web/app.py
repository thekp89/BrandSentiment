"""
Brand Sentiment Dashboard
Flask web application with Tokyo Night theme
"""
import os
import sys
import json
import subprocess
import threading
import sqlite3
import hashlib
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, redirect, url_for, flash, Response, stream_with_context, make_response, abort
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import pandas as pd
import glob
import ollama
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
from Forensics import ForensicProcessor
from Manager import run_full_sentiment_scan
from alerts import dispatch_alerts
from surface import audit_domain_surface

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'brand-sentinel-2026')

# --- AUTH CONFIG ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple User Class (In-Memory or DB later)
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id == '1':
        return User(id='1')
    return None

ADMIN_USERNAME = os.getenv('DASHBOARD_USER', 'admin')
ADMIN_PASSWORD = os.getenv('DASHBOARD_PASS', 'sentinel2026')
ADMIN_USER = {
    'id': '1',
    'username': ADMIN_USERNAME,
    'password_hash': generate_password_hash(ADMIN_PASSWORD)
}

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTES_DIR = os.path.join(BASE_DIR, 'reportes')
RECOLECCION_DIR = os.path.join(BASE_DIR, 'recoleccion')
SPIDERFOOT_DIR = os.path.join(RECOLECCION_DIR, 'spiderfoot')
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
FORENSIC_DB = os.path.join(BASE_DIR, 'fenix.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Forensics Database
try:
    ForensicProcessor(FORENSIC_DB)
except Exception as e:
    print(f"Warning: Could not initialize Forensics DB: {e}")

# Global scan process and state
current_scan_process = None

scan_status = {
    'running': False,
    'progress': 0,
    'current_target': '',
    'log': [],
    'started_at': None,
    'message': 'Listo para escanear'
}

# --- HELPER FUNCTIONS ---

def init_db():
    try:
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        # Forensics Table
        c.execute('''CREATE TABLE IF NOT EXISTS cases
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      name TEXT, 
                      description TEXT, 
                      investigator TEXT, 
                      start_date TEXT, 
                      status TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS evidence
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      case_id INTEGER, 
                      filename TEXT, 
                      file_hash TEXT, 
                      timestamp TEXT, 
                      metadata TEXT, 
                      FOREIGN KEY(case_id) REFERENCES cases(id))''')
        
        # DREAD Risk Table
        c.execute('''CREATE TABLE IF NOT EXISTS spiderfoot_risk
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_name TEXT,
                      finding_hash TEXT,
                      category TEXT,
                      value TEXT,
                      damage INTEGER,
                      reproducibility INTEGER,
                      exploitability INTEGER,
                      affected_users INTEGER,
                      discoverability INTEGER,
                      score REAL,
                      severity TEXT,
                      notes TEXT,
                      escalated INTEGER DEFAULT 0,
                      timestamp TEXT)''')
                      
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error checking/creating DB: {e}")

# Ensure DB exists
if not os.path.exists(os.path.dirname(FORENSIC_DB)):
    os.makedirs(os.path.dirname(FORENSIC_DB), exist_ok=True)
init_db()

def calculate_dread_score(d, r, e, a, disc):
    score = (d + r + e + a + disc) / 5.0
    if score > 8.0: return score, 'CRÍTICO'
    if score > 6.0: return score, 'ALTO'
    return score, 'MEDIO/BAJO'

def get_finding_hash(category, value):
    raw = f"{category}:{value}"
    return hashlib.sha256(raw.encode()).hexdigest()

# --- AUTH ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USER['username'] and check_password_hash(ADMIN_USER['password_hash'], password):
            user = User(id=ADMIN_USER['id'])
            login_user(user)
            next_page = request.args.get('next')
            if next_page and (not next_page.startswith('/') or next_page.startswith('//')):
                next_page = None
            return redirect(next_page or url_for('dashboard'))
        
        flash('Credenciales incorrectas: Usuario o contraseña inválidos.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.before_request
def require_log_in():
    # List of allowed endpoints without login
    allowed_routes = ['login', 'static']
    
    if request.endpoint and request.endpoint not in allowed_routes and not current_user.is_authenticated:
        return redirect(url_for('login'))


def get_targets_files():
    """Get list of available target configuration files."""
    targets = []
    if os.path.exists(CONFIG_DIR):
        for f in os.listdir(CONFIG_DIR):
            if f.endswith('.json') and 'target' in f.lower():
                targets.append(f)
    return targets

def get_recent_scans():
    """Get list of recent scan directories."""
    scans = []
    if os.path.exists(REPORTES_DIR):
        for d in sorted(os.listdir(REPORTES_DIR), reverse=True)[:20]:
            path = os.path.join(REPORTES_DIR, d)
            if os.path.isdir(path):
                # Count files
                csv_count = len([f for f in os.listdir(path) if f.endswith('.csv')])
                img_count = len([f for f in os.listdir(path) if f.endswith('.png')])
                scans.append({
                    'name': d,
                    'date': d.replace('scan_', '').replace('_', ' '),
                    'path': path,
                    'csv_count': csv_count,
                    'img_count': img_count
                })
    return scans

def get_spiderfoot_scans():
    """Get list of available SpiderFoot scan files."""
    scans = []
    if os.path.exists(SPIDERFOOT_DIR):
        for f in sorted(os.listdir(SPIDERFOOT_DIR), reverse=True):
            if f.endswith('.csv'):
                try:
                    stats = os.stat(os.path.join(SPIDERFOOT_DIR, f))
                    mod_time = datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M')
                except:
                    mod_time = "Desconocido"
                
                scans.append({
                    'name': f,
                    'date': mod_time,
                    'size': f"{stats.st_size / 1024:.1f} KB"
                })
    return scans

def parse_spiderfoot_data(scan_name, filename=None):
    """
    Parses SpiderFoot CSV export.
    Returns:
    - stats: { category: count }
    - details: { category: [ {value, source, module, risk, dread...} ] }
    - graph_data: { nodes: [], edges: [] } for Vis.js
    """
    if filename:
        filepath = filename
    else:
        filepath = os.path.join(SPIDERFOOT_DIR, scan_name)
    
    if not os.path.exists(filepath):
        return None, None, None

    try:
        df = pd.read_csv(filepath)
        df.columns = [c.lower() for c in df.columns]
        
        # Standardize columns
        col_map = {}
        for c in df.columns:
            if 'type' in c: col_map['type'] = c
            elif 'data' in c or 'value' in c: col_map['value'] = c
            elif 'module' in c: col_map['module'] = c
            elif 'source' in c: col_map['source'] = c
            
        if not col_map.get('type') or not col_map.get('value'):
             if len(df.columns) >= 2:
                 df.rename(columns={df.columns[0]: 'type', df.columns[1]: 'value'}, inplace=True)
             else:
                 return {}, {}, {}
        else:
            df.rename(columns={v: k for k, v in col_map.items()}, inplace=True)

        # --- RISK LOGIC ---
        high_risk_types = ['Malicious IP', 'Leaked Password', 'Vulnerability', 'Open TCP Port', 'Suspicious URL']
        medium_risk_types = ['Email Address', 'Human Name', 'Operating System', 'Web Server']
        
        def get_risk(row):
            t = row['type']
            if t in high_risk_types: return 'HIGH'
            if t in medium_risk_types: return 'MEDIUM'
            return 'LOW'

        df['risk'] = df.apply(get_risk, axis=1)

        # --- SMART GROUPING (IP -> Ports) ---
        # We want to group "Open TCP Port" findings under their respective "IP Address" if possible
        # SpiderFoot format: Type=Open TCP Port, Value=1.2.3.4:80
        
        stats = df['type'].value_counts().to_dict()
        details = {}
        
        # Graph Data Structures
        nodes = []
        edges = []
        node_ids = set()
        
        # Helper to add node safely
        def add_node(nid, label, group, risk='LOW'):
            if nid not in node_ids:
                nodes.append({
                    'id': nid, 
                    'label': label, 
                    'group': group,
                    'risk': risk
                })
                node_ids.add(nid)

        # --- DREAD Scores from DB ---
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        c.execute("SELECT finding_hash, damage, reproducibility, exploitability, affected_users, discoverability, score, severity, notes FROM spiderfoot_risk WHERE scan_name=?", (scan_name,))
        stored_risks = {r[0]: {'d':r[1], 'r':r[2], 'e':r[3], 'a':r[4], 'disc':r[5], 'score':r[6], 'severity':r[7], 'notes':r[8]} for r in c.fetchall()}
        conn.close()

        for category in stats.keys():
            cat_df = df[df['type'] == category]
            unique_items = {}
            
            for _, row in cat_df.iterrows():
                val = str(row['value'])
                module = row.get('module', 'Unknown')
                source = row.get('source', 'Unknown') # Parent usually
                risk = row.get('risk', 'LOW')
                
                # Check for stored DREAD risk
                f_hash = get_finding_hash(category, val)
                dread_data = stored_risks.get(f_hash)
                
                if dread_data:
                    risk = dread_data['severity'] # Override low/med/high with stored severity

                # --- Graph Logic ---
                # Node for this item
                add_node(val, val, category, risk)
                
                # Node for source (Parent)
                if source and source != val:
                    # Generic group for source if unknown
                    add_node(source, source, 'Source', 'LOW') 
                    # Edge source -> val
                    edges.append({'from': source, 'to': val, 'label': module})

                # --- Grouping Logic ---
                # Special handling for Ports: 1.2.3.4:80 -> IP 1.2.3.4
                if category == 'Open TCP Port' and ':' in val:
                    ip, port = val.split(':', 1)
                    # We treat the IP as the main item, and append port to it
                    if ip not in unique_items:
                         unique_items[ip] = {
                            'value': ip,
                            'display_value': ip,
                            'hash': get_finding_hash(category, ip), # Hash of parent IP? Maybe complicated.
                            'count': 0,
                            'modules': set(),
                            'sources': set(),
                            'ports': set(),
                            'risk': 'HIGH', # Default
                            'dread': None
                        }
                    unique_items[ip]['ports'].add(port)
                    unique_items[ip]['count'] += 1
                    unique_items[ip]['modules'].add(module)
                    unique_items[ip]['sources'].add(source)
                    continue

                if val not in unique_items:
                    unique_items[val] = {
                        'value': val,
                        'display_value': val,
                        'hash': f_hash,
                        'count': 0,
                        'modules': set(),
                        'sources': set(),
                        'risk': risk,
                        'dread': dread_data
                    }
                
                unique_items[val]['count'] += 1
                unique_items[val]['modules'].add(module)
                unique_items[val]['sources'].add(source)
            
            # Serialize
            details[category] = []
            for item in unique_items.values():
                item['modules'] = list(item['modules'])
                item['sources'] = list(item['sources'])
                if 'ports' in item:
                    item['ports'] = sorted(list(item['ports']), key=lambda x: int(x) if x.isdigit() else x)
                    item['display_value'] = f"{item['value']} (Ports: {', '.join(item['ports'])})"
                    # For ports, we might want to check if the IP itself was scored, but we stick to item logic for now
                details[category].append(item)

        graph_data = {'nodes': nodes, 'edges': edges}
        return stats, details, graph_data
        
    except Exception as e:
        print(f"Error parsing SpiderFoot file: {e}")
        return {}, {}, {}

def get_scan_results(scan_name):
    """Load results from a specific scan."""
    scan_path = os.path.join(REPORTES_DIR, scan_name)
    results = {'csv_files': [], 'images': [], 'html_files': []}
    
    if os.path.exists(scan_path):
        for f in os.listdir(scan_path):
            if f.endswith('.csv'):
                results['csv_files'].append(f)
            elif f.endswith(('.png', '.jpg', '.jpeg')):
                results['images'].append(f)
            elif f.endswith('.html'):
                results['html_files'].append(f)
    
    return results

def load_csv_data(scan_name, csv_file):
    """Load and return CSV data as JSON."""
    path = os.path.join(REPORTES_DIR, scan_name, csv_file)
    if os.path.exists(path):
        df = pd.read_csv(path)
        return df.to_dict(orient='records')
    return []

def load_all_scan_data(scan_name=None, filters=None, include_history=False, exclude_backlinks=False):
    """Load all CSV data from a scan with optional filters and history."""
    scan_path = os.path.join(REPORTES_DIR, scan_name)
    all_data = []
    
    # helper to load a single scan dir
    def load_dir(path, is_hist=False, origin_name=""):
        data = []
        if not os.path.exists(path): return []
        for root, dirs, files in os.walk(path):
            for f in files:
                if f.endswith('.csv'):
                    try:
                        df = pd.read_csv(os.path.join(root, f))
                        if not df.empty:
                            df['_source_file'] = f
                            df['is_historical'] = is_hist
                            if is_hist:
                                df['scan_origin'] = origin_name
                            data.append(df)
                    except Exception as e:
                        print(f"Error loading {f}: {e}")
        return data

    # 1. Load Current Scan
    all_data.extend(load_dir(scan_path, is_hist=False))
    
    # 2. Load History if requested
    if include_history:
        # Get recent scans, exclude current
        recent = get_recent_scans()
        # Filter out current scan
        history_scans = [s for s in recent if s['name'] != scan_name]
        # Limit to last 5 to prevent performance issues
        for h_scan in history_scans[:5]:
            all_data.extend(load_dir(h_scan['path'], is_hist=True, origin_name=h_scan['name']))

    if not all_data:
        return [], {}
    
    # Combine all dataframes
    try:
        combined = pd.concat(all_data, ignore_index=True)
        
        # Deduplication Strategy:
        # We want to keep CURRENT items over HISTORICAL items.
        # So we sort by is_historical (False first -> 0, True -> 1) 
        # allowing drop_duplicates(keep='first') to preserve the current one.
        
        if 'is_historical' not in combined.columns:
            combined['is_historical'] = False
            
        combined = combined.sort_values(by=['is_historical'])
        
        # Deduplicate by link if possible
        if 'link' in combined.columns:
            combined = combined.drop_duplicates(subset=['link'], keep='first')
        
        # Norm comment deduplication
        if 'comentario' in combined.columns:
            # Simple normalization for deduplication
            combined['_norm_text'] = combined['comentario'].astype(str).str.lower().str.replace(r'\s+', ' ', regex=True).str.strip()
            combined = combined.drop_duplicates(subset=['_norm_text'], keep='first')
            combined = combined.drop(columns=['_norm_text'])
            
    except Exception as e:
        print(f"Error combining data: {e}")
        return [], {}
    
    # Flexible column mapping
    col_map = {
        'sentiment': next((c for c in ['Etiqueta', 'etiqueta', 'Sentiment', 'sentiment'] if c in combined.columns), None),
        'source': next((c for c in ['Fuente', 'fuente', 'Source', 'source'] if c in combined.columns), None),
        'entity': next((c for c in ['Entidad', 'entidad', 'Entity', 'target'] if c in combined.columns), None),
        'risk': next((c for c in ['Nivel_Riesgo', 'AI_Risk', 'riesgo'] if c in combined.columns), None),
        'category': next((c for c in ['AI_Category', 'categoria_ia'] if c in combined.columns), None),
        'type': next((c for c in ['Tipo_Competidor', 'tipo_competidor', 'competitor_type'] if c in combined.columns), None),
        'date': next((c for c in ['fecha', 'date', 'Timestamp'] if c in combined.columns), None)
    }

    # Get unique values for filter options (from ALL data including history)
    filter_options = {
        'sentiments': combined[col_map['sentiment']].dropna().unique().tolist() if col_map['sentiment'] else [],
        'sources': combined[col_map['source']].dropna().unique().tolist() if col_map['source'] else [],
        'entities': combined[col_map['entity']].dropna().unique().tolist() if col_map['entity'] else [],
        'risk_levels': combined[col_map['risk']].dropna().unique().tolist() if col_map['risk'] else [],
        'categories': combined[col_map['category']].dropna().unique().tolist() if col_map['category'] else [],
        'types': combined[col_map['type']].dropna().unique().tolist() if col_map['type'] else []
    }
    
    
    # Backlink Filter
    if exclude_backlinks and 'is_backlink' in combined.columns:
        combined = combined[combined['is_backlink'] == False]

    # Apply filters if provided
    if filters:
        if filters.get('sentiment') and col_map['sentiment']:
            combined = combined[combined[col_map['sentiment']] == filters['sentiment']]
        if filters.get('source') and col_map['source']:
            combined = combined[combined[col_map['source']] == filters['source']]
        if filters.get('entity') and col_map['entity']:
            combined = combined[combined[col_map['entity']] == filters['entity']]
        if filters.get('risk') and col_map['risk']:
            combined = combined[combined[col_map['risk']] == filters['risk']]
        if filters.get('category') and col_map['category']:
            combined = combined[combined[col_map['category']] == filters['category']]
        if filters.get('type') and col_map['type']:
            combined = combined[combined[col_map['type']] == filters['type']]
        
        # New: Filter for Historical
        # If user explicitly wants ONLY history or ONLY current, we could add logic here
        # But for now 'include_history' just appends. 
            
        if filters.get('search'):
            search_term = str(filters['search']).lower()
            text_cols = ['comentario', 'Texto_Limpio', 'AI_Justification', 'Texto']
            text_cols = [c for c in text_cols if c in combined.columns]
            
            if text_cols:
                mask = pd.Series([False] * len(combined))
                for col in text_cols:
                    mask |= combined[col].astype(str).str.lower().str.contains(search_term, na=False)
                combined = combined[mask]
    
    # Sort by date
    if col_map['date']:
        try:
            combined = combined.sort_values(col_map['date'], ascending=False)
        except:
            pass
    
    # Replace NaN with empty string for JSON safety
    combined = combined.fillna('')
    
    # Add mapped columns for consistent UI
    if col_map['sentiment']: combined['Etiqueta'] = combined[col_map['sentiment']]
    if col_map['source']: combined['Fuente'] = combined[col_map['source']]
    if col_map['entity']: combined['Entidad'] = combined[col_map['entity']]
    if col_map['risk']: combined['Nivel_Riesgo'] = combined[col_map['risk']]
    if col_map['date']: combined['fecha'] = combined[col_map['date']]
    
    # Text and link aliasing
    if 'comentario' not in combined.columns:
        cmt_col = next((c for c in ['Texto_Limpio', 'texto', 'Texto', 'content'] if c in combined.columns), None)
        if cmt_col: combined['comentario'] = combined[cmt_col]
    
    if 'link' not in combined.columns:
        lnk_col = next((c for c in ['URL', 'url', 'Link'] if c in combined.columns), None)
        if lnk_col: combined['link'] = combined[lnk_col]
        
    # BACKLINK IDENTIFICATION
    # Check if 'id' column starts with 'backlink_' OR 'Fuente' is 'web_externas'
    is_id_backlink = combined['id'].astype(str).str.startswith('backlink_') if 'id' in combined.columns else pd.Series(False, index=combined.index)
    is_source_backlink = (combined['Fuente'] == 'web_externas') if 'Fuente' in combined.columns else pd.Series(False, index=combined.index)
    
    combined['is_backlink'] = is_id_backlink | is_source_backlink
    
    # EXCLUDE SUBDOMAINS (internal domains should not be treated as external backlink)
    if 'link' in combined.columns:
        try:
            with open(os.path.join(BASE_DIR, "config", "official_sources.json"), "r") as f:
                official_doms = json.load(f).get("dominios_oficiales", [])
        except Exception:
            official_doms = []
        
        if official_doms:
            pattern = r"(" + "|".join([re.escape(d) for d in official_doms]) + r")"
            is_internal_domain = combined['link'].astype(str).str.contains(pattern, case=False, na=False)
            combined['is_backlink'] = combined['is_backlink'] & (~is_internal_domain)
    
    return combined.to_dict(orient='records'), filter_options

def get_stats_for_scan(scan_name=None, exclude_backlinks=False):
    """Calculate statistics for a specific scan or latest."""
    stats = {
        'scan_name': '',
        'total_mentions': 0,
        'positive': 0,
        'negative': 0,
        'neutral': 0,
        'noise': 0,
        'promocion': 0,
        'high_risk': 0,
        'avg_polarity': 0.0,
        'positive_rate': 0.0,
        'risk_rate': 0.0,
        'sources': {},
        'categories': {},
        'entities': {},
        'entities_detail': {}, # {entity: {pos, neg, neu, total, source_categories}}
        'sources_detail': {},  # {source: {pos, neg, neu, total}}
        'source_categories': {}, # Global source category counts
        'backlinks_count': 0,
        'types': {},
        'types_detail': {} # {type: {pos, neg, neu, total, source_categories}}
    }
    
    if not os.path.exists(REPORTES_DIR):
        return stats
        
    # Find target scan or most recent
    scan_dirs = sorted([d for d in os.listdir(REPORTES_DIR) if os.path.isdir(os.path.join(REPORTES_DIR, d))], reverse=True)
    
    if scan_name and scan_name in scan_dirs:
        target_scan = scan_name
    elif scan_dirs:
        target_scan = scan_dirs[0]
    else:
        return stats
    
    stats['scan_name'] = target_scan
    scan_path = os.path.join(REPORTES_DIR, target_scan)
    
    polarities = []
    
    # Load all data for the target scan, applying backlink exclusion if requested
    data_list, _ = load_all_scan_data(target_scan, exclude_backlinks=exclude_backlinks)

    if not data_list:
        return stats
        
    # Convert list of dicts to DataFrame for easier processing
    df_combined = pd.DataFrame(data_list)
    
    # Initialize source categories
    stats['source_categories'] = {
        'OFICIAL_REDES': 0, 'OFICIAL_BLOG': 0, 'MENCIONES_REDES': 0, 'NOTICIAS_EXTERNAS': 0, 'RUIDO': 0
    }
    
    # Now use df_combined for all stats
    stats['total_mentions'] = len(df_combined)
    stats['backlinks_count'] = len(df_combined[df_combined['is_backlink'] == True]) if 'is_backlink' in df_combined.columns else 0
    
    # Sentiment counts - check column name (Etiqueta)
    sent_col = 'Etiqueta' if 'Etiqueta' in df_combined.columns else None
    if sent_col:
        stats['positive'] = len(df_combined[df_combined[sent_col] == 'Positivo'])
        stats['negative'] = len(df_combined[df_combined[sent_col] == 'Negativo'])
        stats['neutral'] = len(df_combined[df_combined[sent_col] == 'Neutro'])
        stats['noise'] = len(df_combined[df_combined[sent_col] == 'Ruido'])
        stats['promocion'] = len(df_combined[df_combined[sent_col] == 'Promocion'])
                    
    # Polarity
    if 'Polaridad' in df_combined.columns:
        polarities = df_combined['Polaridad'].dropna().tolist()
    
    # Risk - check actual column name (Nivel_Riesgo, AI_Risk)
    risk_col = None
    for col in ['Nivel_Riesgo', 'AI_Risk', 'riesgo']:
        if col in df_combined.columns:
            risk_col = col
            break
    if risk_col:
        high_risk_df = df_combined[df_combined[risk_col].isin(['CRITICO', 'ALTO', 'CRITICAL', 'HIGH'])]
        stats['high_risk'] = len(high_risk_df)
    
    # AI Categories - check actual column name (AI_Category)
    cat_col = None
    for col in ['AI_Category', 'categoria_ia']:
        if col in df_combined.columns:
            cat_col = col
            break
    if cat_col:
        cat_counts = df_combined[cat_col].value_counts()
        for cat, count in cat_counts.items():
            if cat and str(cat) != 'N/A':
                stats['categories'][cat] = int(count)
    
    # Find columns for granular breakdown
    src_col = next((c for c in ['Fuente', 'fuente', 'source'] if c in df_combined.columns), None)
    cat_src_col = next((c for c in ['Categoria_Fuente', 'categoria_fuente'] if c in df_combined.columns), None)
    ent_col = next((c for c in ['Entidad', 'entidad', 'target'] if c in df_combined.columns), None)
    typ_col = next((c for c in ['Tipo_Competidor', 'tipo_competidor', 'competitor_type'] if c in df_combined.columns), None)

    # Update Granular Stats
    for _, row in df_combined.iterrows():
        sentiment = str(row[sent_col]) if sent_col and pd.notna(row[sent_col]) else 'Unknown'
        
        # Source Category
        if cat_src_col and pd.notna(row[cat_src_col]):
            cat_src = str(row[cat_src_col])
            if cat_src in stats['source_categories']:
                stats['source_categories'][cat_src] += 1
        
        # Source detail
        if src_col and pd.notna(row[src_col]):
            src = str(row[src_col])
            stats['sources'][src] = stats['sources'].get(src, 0) + 1
            if src not in stats['sources_detail']:
                stats['sources_detail'][src] = {'Positivo': 0, 'Negativo': 0, 'Neutro': 0, 'Ruido': 0, 'Promocion': 0, 'Backlinks': 0, 'Total': 0}
            stats['sources_detail'][src]['Total'] += 1
            if sentiment in stats['sources_detail'][src]:
                stats['sources_detail'][src][sentiment] += 1
            if row.get('is_backlink', False):
                stats['sources_detail'][src]['Backlinks'] += 1
        
        if ent_col and pd.notna(row[ent_col]):
            ent = str(row[ent_col])
            stats['entities'][ent] = stats['entities'].get(ent, 0) + 1
            if ent not in stats['entities_detail']:
                stats['entities_detail'][ent] = {
                    'Positivo': 0, 'Negativo': 0, 'Neutro': 0, 'Ruido': 0, 'Promocion': 0, 'Backlinks': 0, 'Total': 0,
                    'source_categories': {'OFICIAL_REDES': 0, 'OFICIAL_BLOG': 0, 'MENCIONES_REDES': 0, 'NOTICIAS_EXTERNAS': 0, 'RUIDO': 0}
                }
            
            stats['entities_detail'][ent]['Total'] += 1
            
            # Prioritize Backlink categorization for the visual bar
            if row.get('is_backlink', False):
                stats['entities_detail'][ent]['Backlinks'] += 1
            else:
                if sentiment in stats['entities_detail'][ent]:
                    stats['entities_detail'][ent][sentiment] += 1
            
            # Aggregate Categoria_Fuente for Entity
            if 'Categoria_Fuente' in row and pd.notna(row['Categoria_Fuente']):
                cat_fuente = str(row['Categoria_Fuente'])
                if cat_fuente in stats['entities_detail'][ent]['source_categories']:
                     stats['entities_detail'][ent]['source_categories'][cat_fuente] += 1
                else:
                     # Fallback or unknown category
                     pass
                     
        if typ_col and pd.notna(row[typ_col]):
            ct = str(row[typ_col])
            stats['types'][ct] = stats['types'].get(ct, 0) + 1
            if ct not in stats['types_detail']:
                stats['types_detail'][ct] = {
                    'Positivo': 0, 'Negativo': 0, 'Neutro': 0, 'Ruido': 0, 'Promocion': 0, 'Backlinks': 0, 'Total': 0,
                    'source_categories': {'OFICIAL_REDES': 0, 'OFICIAL_BLOG': 0, 'MENCIONES_REDES': 0, 'NOTICIAS_EXTERNAS': 0, 'RUIDO': 0}
                }
            
            stats['types_detail'][ct]['Total'] += 1
            
            if row.get('is_backlink', False):
                stats['types_detail'][ct]['Backlinks'] += 1
            else:
                if sentiment in stats['types_detail'][ct]:
                    stats['types_detail'][ct][sentiment] += 1
            
            if 'Categoria_Fuente' in row and pd.notna(row['Categoria_Fuente']):
                cat_fuente = str(row['Categoria_Fuente'])
                if cat_fuente in stats['types_detail'][ct]['source_categories']:
                     stats['types_detail'][ct]['source_categories'][cat_fuente] += 1
        
    # Aggregate Global Source Categories
    if 'Categoria_Fuente' in df_combined.columns:
        cat_counts = df_combined['Categoria_Fuente'].value_counts()
        for cat, count in cat_counts.items():
            if cat in stats['source_categories']:
                stats['source_categories'][cat] = int(count)
            else:
                # Add unexpected categories just in case
                stats['source_categories'][str(cat)] = int(count)
    
    # Calculate rates
    if stats['total_mentions'] > 0:
        stats['positive_rate'] = round((stats['positive'] / stats['total_mentions']) * 100, 1)
        stats['risk_rate'] = round((stats['high_risk'] / stats['total_mentions']) * 100, 1)
    
    if polarities:
        stats['avg_polarity'] = round(sum(polarities) / len(polarities), 2)
    
    return stats

# Routes
@app.route('/')
def dashboard():
    """Main dashboard page."""
    scan_name = request.args.get('scan', None)
    exclude_backlinks = request.args.get('exclude_backlinks', 'false').lower() == 'true'
    stats = get_stats_for_scan(scan_name, exclude_backlinks=exclude_backlinks)
    recent_scans = get_recent_scans()
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans, selected_scan=scan_name)

@app.route('/risk')
def risk_page():
    """Risk assessment page."""
    scan_name = request.args.get('scan', None)
    stats = get_stats_for_scan(scan_name)
    recent_scans = get_recent_scans()
    return render_template('risk.html', stats=stats, recent_scans=recent_scans, active_module='sentiment')

@app.route('/entities')
def entities_page():
    """By entity analysis page."""
    scan_name = request.args.get('scan', None)
    stats = get_stats_for_scan(scan_name)
    recent_scans = get_recent_scans()
    
    # Fetch mentions for interactive filtering
    data, _ = load_all_scan_data(stats['scan_name'])
    
    # Simplify data for client-side use
    simple_mentions = []
    for m in data:
        simple_mentions.append({
            'entity': m.get('Entidad', 'Unknown'),
            'sentiment': m.get('Etiqueta', 'Neutro'),
            'is_backlink': m.get('is_backlink', False),
            'source': m.get('Fuente', 'Unknown')
        })
        
    return render_template('entities.html', 
                           stats=stats, 
                           recent_scans=recent_scans, 
                           mentions_json=simple_mentions,
                           active_module='sentiment')

@app.route('/entity/<entity_name>')
def entity_details(entity_name):
    """Detailed view for a specific entity."""
    scan_name = request.args.get('scan', None)
    exclude_backlinks = request.args.get('exclude_backlinks', 'false').lower() == 'true'
    
    stats = get_stats_for_scan(scan_name, exclude_backlinks=exclude_backlinks)
    recent_scans = get_recent_scans()
    
    # Get specific stats for this entity
    entity_stats = stats.get('entities_detail', {}).get(entity_name, {
        'Total': 0, 'Positivo': 0, 'Negativo': 0, 'Neutro': 0, 'Ruido': 0, 'Promocion': 0, 'Backlinks': 0,
        'source_categories': {'OFICIAL_REDES': 0, 'OFICIAL_BLOG': 0, 'MENCIONES_REDES': 0, 'NOTICIAS_EXTERNAS': 0, 'RUIDO': 0}
    })
    
    # Fetch mentions for this entity
    # Reuse load_all_scan_data filtering logic but strictly for this entity
    data, _ = load_all_scan_data(stats['scan_name'], {'entity': entity_name}, exclude_backlinks=exclude_backlinks)
    
    return render_template('entity_details.html', 
                           entity=entity_name, 
                           stats=entity_stats, 
                           mentions=data,
                           scan_name=stats['scan_name'],
                           recent_scans=recent_scans,
                           active_module='sentiment')

@app.route('/sources')
def sources_page():
    """By source analysis page."""
    scan_name = request.args.get('scan', None)
    stats = get_stats_for_scan(scan_name)
    recent_scans = get_recent_scans()
    return render_template('sources.html', stats=stats, recent_scans=recent_scans, active_module='sentiment')

@app.route('/scan')
def scan_page():
    """Scan configuration page."""
    targets_files = get_targets_files()
    return render_template('scan.html', targets_files=targets_files, scan_status=scan_status, active_module='sentiment')

@app.route('/results')
def results_page():
    """Results viewer page."""
    scans = get_recent_scans()
    return render_template('results.html', scans=scans, active_module='sentiment')

@app.route('/results/<scan_name>')
def scan_details(scan_name):
    """View specific scan results."""
    results = get_scan_results(scan_name)
    stats = get_stats_for_scan(scan_name)
    return render_template('scan_details.html', scan_name=scan_name, results=results, stats=stats)

@app.route('/explorer')
def data_explorer():
    """Data explorer with advanced filters."""
    scan_name = request.args.get('scan', None)
    exclude_backlinks = request.args.get('exclude_backlinks', 'false').lower() == 'true'
    recent_scans = get_recent_scans()
    
    # Get scan name (default to latest)
    if not scan_name and recent_scans:
        scan_name = recent_scans[0]['name']
        # Load data (no filters initially)
        data_list, _ = load_all_scan_data(scan_name, exclude_backlinks=exclude_backlinks)
        
        if not data_list:
            return render_template('explorer.html', 
                           scan_name=scan_name,
                           recent_scans=recent_scans,
                           filter_options={}, # No filter options if no data
                           active_module='sentiment')
    
    # Get filter options from data
    _, filter_options = load_all_scan_data(scan_name, exclude_backlinks=exclude_backlinks) if scan_name else ([], {})
    
    return render_template('explorer.html', 
                           scan_name=scan_name,
                           recent_scans=recent_scans,
                           filter_options=filter_options,
                           active_module='sentiment')

def get_alert_channels_status():
    """Check configuration status of alert notification channels."""
    return {
        'slack': bool(os.getenv("SLACK_WEBHOOK_URL")),
        'discord': bool(os.getenv("DISCORD_WEBHOOK_URL")),
        'telegram': bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID")),
        'smtp': bool(os.getenv("SMTP_SERVER") and os.getenv("ALERT_EMAIL_TO"))
    }

@app.route('/targets')
def targets_page():
    """Targets and Competitors configuration page."""
    targets_path = os.path.join(CONFIG_DIR, 'targets.json')
    official_path = os.path.join(CONFIG_DIR, 'official_sources.json')
    
    targets_data = {}
    if os.path.exists(targets_path):
        try:
            with open(targets_path, 'r', encoding='utf-8') as f:
                targets_data = json.load(f)
        except Exception as e:
            print(f"Error loading targets.json: {e}")
            
    official_sources = {'dominios_oficiales': [], 'cuentas_oficiales': []}
    if os.path.exists(official_path):
        try:
            with open(official_path, 'r', encoding='utf-8') as f:
                official_sources = json.load(f)
        except Exception as e:
            print(f"Error loading official_sources.json: {e}")

    return render_template(
        'targets.html',
        targets_data=targets_data,
        official_sources=official_sources,
        alert_status=get_alert_channels_status(),
        active_module='targets'
    )

@app.route('/api/groups/save', methods=['POST'])
def api_groups_save():
    """Create or update a competition group/table."""
    data = request.json or {}
    group_key = data.get('group_key', '').strip()
    descripcion = data.get('descripcion', '').strip()
    original_key = data.get('original_key', '').strip()

    if not group_key:
        return jsonify({'success': False, 'error': 'El nombre o identificador de la tabla es requerido'}), 400

    # Clean key: spaces to underscore, alphanumeric, underscore and dash only
    clean_key = re.sub(r'[^a-zA-Z0-9_-]', '_', group_key).strip('_')
    if not clean_key:
        return jsonify({'success': False, 'error': 'Identificador de tabla inválido'}), 400

    targets_path = os.path.join(CONFIG_DIR, 'targets.json')
    targets_data = {}
    if os.path.exists(targets_path):
        try:
            with open(targets_path, 'r', encoding='utf-8') as f:
                targets_data = json.load(f)
        except Exception as e:
            return jsonify({'success': False, 'error': f'Error al leer targets: {e}'}), 500

    # Renaming existing group
    if original_key and original_key in targets_data:
        if original_key == 'Grupo_Propio' and clean_key != 'Grupo_Propio':
            clean_key = 'Grupo_Propio'  # Keep Grupo_Propio key for brand identity anchor

        existing_targets = targets_data[original_key].get('targets', [])
        if original_key != clean_key:
            del targets_data[original_key]

        targets_data[clean_key] = {
            'descripcion': descripcion or f'Tabla de {clean_key}',
            'targets': existing_targets
        }
    else:
        # Create new group if doesn't exist
        if clean_key not in targets_data:
            targets_data[clean_key] = {
                'descripcion': descripcion or f'Tabla de {clean_key}',
                'targets': []
            }
        else:
            targets_data[clean_key]['descripcion'] = descripcion or targets_data[clean_key].get('descripcion', '')

    try:
        with open(targets_path, 'w', encoding='utf-8') as f:
            json.dump(targets_data, f, indent=4, ensure_ascii=False)
        return jsonify({'success': True, 'message': 'Tabla de competencia guardada correctamente', 'group_key': clean_key})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error al guardar tabla: {e}'}), 500

@app.route('/api/groups/delete', methods=['DELETE', 'POST'])
def api_groups_delete():
    """Delete a whole competition group/table."""
    group_key = request.args.get('group_key') or (request.json and request.json.get('group_key'))
    if not group_key:
        return jsonify({'success': False, 'error': 'Parámetro group_key requerido'}), 400

    if group_key == 'Grupo_Propio':
        return jsonify({'success': False, 'error': 'No se puede eliminar la tabla de la Marca Propia (Identidad)'}), 400

    targets_path = os.path.join(CONFIG_DIR, 'targets.json')
    if not os.path.exists(targets_path):
        return jsonify({'success': False, 'error': 'Archivo targets.json no encontrado'}), 404

    try:
        with open(targets_path, 'r', encoding='utf-8') as f:
            targets_data = json.load(f)

        if group_key in targets_data:
            del targets_data[group_key]
            with open(targets_path, 'w', encoding='utf-8') as f:
                json.dump(targets_data, f, indent=4, ensure_ascii=False)
            return jsonify({'success': True, 'message': f'Tabla {group_key} eliminada correctamente'})
        else:
            return jsonify({'success': False, 'error': f'Tabla {group_key} no encontrada'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/targets/save', methods=['POST'])
def api_targets_save():
    """Add or update a target."""
    data = request.json or {}
    group = data.get('group', '').strip()
    name = data.get('name', '').strip()
    domain = data.get('domain', '').strip()
    busqueda = data.get('busqueda') or data.get('keywords', [])
    original_group = data.get('original_group', '').strip()
    original_name = data.get('original_name', '').strip()

    if not group or not name:
        return jsonify({'success': False, 'error': 'El grupo y el nombre son requeridos'}), 400

    targets_path = os.path.join(CONFIG_DIR, 'targets.json')
    targets_data = {}
    if os.path.exists(targets_path):
        try:
            with open(targets_path, 'r', encoding='utf-8') as f:
                targets_data = json.load(f)
        except Exception as e:
            return jsonify({'success': False, 'error': f'Error al leer targets: {e}'}), 500

    # If updating an existing target, remove original first
    if original_group and original_name and original_group in targets_data:
        targets_data[original_group]['targets'] = [
            t for t in targets_data[original_group].get('targets', [])
            if t.get('nombre') != original_name
        ]

    # Ensure target group exists
    if group not in targets_data:
        targets_data[group] = {
            'descripcion': f'Grupo {group}',
            'targets': []
        }

    # Clean existing target with same name in destination group if any
    targets_data[group]['targets'] = [
        t for t in targets_data[group].get('targets', [])
        if t.get('nombre') != name
    ]

    # Append updated/new target
    new_target = {
        'nombre': name,
        'dominio': domain,
        'busqueda': busqueda if isinstance(busqueda, list) else [b.strip() for b in str(busqueda).split(',') if b.strip()]
    }
    targets_data[group]['targets'].append(new_target)

    try:
        with open(targets_path, 'w', encoding='utf-8') as f:
            json.dump(targets_data, f, indent=4, ensure_ascii=False)
        return jsonify({'success': True, 'message': 'Objetivo guardado exitosamente'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error al guardar: {e}'}), 500

@app.route('/api/targets/delete', methods=['DELETE', 'POST'])
def api_targets_delete():
    """Delete a target from configuration."""
    group = request.args.get('group') or (request.json and request.json.get('group'))
    name = request.args.get('name') or (request.json and request.json.get('name'))

    if not group or not name:
        return jsonify({'success': False, 'error': 'Parámetros group y name requeridos'}), 400

    targets_path = os.path.join(CONFIG_DIR, 'targets.json')
    if not os.path.exists(targets_path):
        return jsonify({'success': False, 'error': 'Archivo targets.json no encontrado'}), 404

    try:
        with open(targets_path, 'r', encoding='utf-8') as f:
            targets_data = json.load(f)

        if group in targets_data:
            targets_data[group]['targets'] = [
                t for t in targets_data[group].get('targets', [])
                if t.get('nombre') != name
            ]
            with open(targets_path, 'w', encoding='utf-8') as f:
                json.dump(targets_data, f, indent=4, ensure_ascii=False)
            return jsonify({'success': True, 'message': 'Objetivo eliminado correctamente'})
        else:
            return jsonify({'success': False, 'error': f'Grupo {group} no encontrado'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/official_sources/save', methods=['POST'])
def api_official_sources_save():
    """Save official domains and social media accounts."""
    data = request.json or {}
    domains = data.get('dominios_oficiales', [])
    accounts = data.get('cuentas_oficiales', [])

    official_path = os.path.join(CONFIG_DIR, 'official_sources.json')
    content = {
        'dominios_oficiales': domains,
        'cuentas_oficiales': accounts
    }
    try:
        with open(official_path, 'w', encoding='utf-8') as f:
            json.dump(content, f, indent=4, ensure_ascii=False)
        return jsonify({'success': True, 'message': 'Fuentes oficiales actualizadas'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/surface')
def surface_page():
    """Attack Surface and Domain Security page."""
    default_domain = "example.com"
    targets_path = os.path.join(CONFIG_DIR, 'targets.json')
    if os.path.exists(targets_path):
        try:
            with open(targets_path, 'r', encoding='utf-8') as f:
                tdata = json.load(f)
                for g in tdata.values():
                    for tgt in g.get('targets', []):
                        if tgt.get('dominio'):
                            default_domain = tgt['dominio']
                            break
                    if default_domain != "example.com":
                        break
        except Exception:
            pass

    return render_template('surface.html', default_domain=default_domain, active_module='surface')

@app.route('/api/surface/audit', methods=['POST'])
def api_surface_audit():
    """Run an attack surface audit on a domain."""
    data = request.json or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'error': 'Dominio no provisto'}), 400

    try:
        audit_res = audit_domain_surface(domain)
        return jsonify({'success': True, 'audit': audit_res})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts/test', methods=['POST'])
def api_alerts_test():
    """Test webhook notifications across active channels."""
    try:
        results = dispatch_alerts(
            title="Prueba de Alerta Brand Sentinel",
            details="Mensaje de verificación de canal de alertas emitido desde el panel de control.",
            severity="INFO"
        )
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export/<fmt>/<scan_name>')
def api_export_scan(fmt, scan_name):
    """Export scan results in CSV, JSON, or Excel format."""
    safe_scan = secure_filename(scan_name)
    scan_dir = os.path.join(REPORTES_DIR, safe_scan)
    if not os.path.exists(scan_dir):
        abort(404, description="Escaneo no encontrado")

    records, _ = load_all_scan_data(safe_scan)
    if not records:
        csv_files = [f for f in os.listdir(scan_dir) if f.endswith('.csv')]
        if csv_files:
            df = pd.read_csv(os.path.join(scan_dir, csv_files[0]))
            records = df.to_dict(orient='records')
        else:
            records = []

    df = pd.DataFrame(records)

    fmt = fmt.lower()
    if fmt == 'json':
        response = make_response(json.dumps(records, indent=2, ensure_ascii=False))
        response.headers["Content-Disposition"] = f"attachment; filename={safe_scan}_export.json"
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response
    elif fmt == 'csv':
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        response = make_response(csv_buf.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={safe_scan}_export.csv"
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        return response
    elif fmt in ('xlsx', 'excel'):
        excel_buf = io.BytesIO()
        with pd.ExcelWriter(excel_buf, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Resultados')
        excel_buf.seek(0)
        response = make_response(excel_buf.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={safe_scan}_export.xlsx"
        response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return response
    else:
        return jsonify({'error': f'Formato {fmt} no soportado. Use csv, json o xlsx.'}), 400

@app.route('/api/stats')
def api_stats():
    """Get dashboard statistics."""
    scan_name = request.args.get('scan', None)
    return jsonify(get_stats_for_scan(scan_name))

@app.route('/api/ai/models')
@login_required
def get_ai_models():
    """Lista modelos disponibles en Ollama local."""
    try:
        models_info = ollama.list()
        # La librería actual devuelve un objeto con atributo 'models'
        # y cada modelo tiene un atributo 'model' (no 'name')
        if hasattr(models_info, 'models'):
            model_list = [m.model for m in models_info.models]
        else:
            # Fallback para versiones que devuelven diccionarios
            model_list = [m.get('name', m.get('model', 'unknown')) for m in models_info.get('models', [])]
        return jsonify({'models': model_list})
    except Exception as e:
        return jsonify({'models': ['mistral'], 'error': str(e)})

@app.route('/api/recoleccion/list')
@login_required
def list_recoleccion_files():
    """Lista archivos CSV en la carpeta recoleccion."""
    pattern = os.path.join(BASE_DIR, 'recoleccion', '*.csv')
    files = glob.glob(pattern)
    # Ordenar por fecha de modificación (más nuevos primero)
    files.sort(key=os.path.getmtime, reverse=True)
    
    file_list = []
    for f in files:
        file_list.append({
            'name': os.path.basename(f),
            'size': os.path.getsize(f),
            'modified': datetime.fromtimestamp(os.path.getmtime(f)).strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({'files': file_list})

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    """Start a new scan."""
    global scan_status
    
    if scan_status['running']:
        return jsonify({'error': 'El escaneo ya se está ejecutando', 'running': True}), 400
    
    data = request.json or {}
    targets_file = data.get('targets_file', 'config/targets.json')
    skip_ai = data.get('skip_ai', False)
    include_backlinks = data.get('include_backlinks', False)
    mode = data.get('mode', 'new')
    archivo_especifico = data.get('archivo_especifico')
    model_name = data.get('model_name')
    
    def run_scan():
        global scan_status, current_scan_process
        scan_status['running'] = True
        scan_status['progress'] = 0
        scan_status['log'] = ['Iniciando escaneo...']
        scan_status['started_at'] = datetime.now().isoformat()
        scan_status['message'] = 'Ejecutando escaneo...'
        scan_status['current_target'] = ''
        
        if mode == "new":
            cmd = [
                sys.executable, 
                os.path.join(BASE_DIR, 'Manager.py'),
                '--mode', 'full_auto',
                '--targets-file', targets_file
            ]
            if not skip_ai:
                cmd.append('--relaxed')
            if include_backlinks:
                cmd.append('--include-backlinks')
        elif mode == "custom":
             # Análisis de un archivo específico
             target_path = os.path.join(BASE_DIR, 'recoleccion', archivo_especifico) if archivo_especifico else None
             if not target_path or not os.path.exists(target_path):
                 scan_status['log'].append(f"Error: Archivo {archivo_especifico} no encontrado.")
                 scan_status['message'] = "Error: Archivo no encontrado."
                 scan_status['running'] = False
                 return
             
             cmd = [
                 sys.executable,
                 os.path.join(BASE_DIR, 'Sentinel.py'),
                 '--archivo', target_path
             ]
             if skip_ai: cmd.append('--skip-ai')
             if model_name: cmd.extend(['--model', model_name])
             scan_status['progress'] = 50
        else:
            # MODE RESUME: Solo ejecutar Sentinel sobre el último master
            pattern = os.path.join(BASE_DIR, 'recoleccion', 'master_input_*.csv')
            files = glob.glob(pattern)
            if not files:
                scan_status['log'].append("Error: No se encontró archivo maestro para reanudar.")
                scan_status['message'] = "Error: No hay escaneo previo."
                scan_status['running'] = False
                return
            
            latest_master = max(files, key=os.path.getctime)
            scan_status['log'].append(f"Reanudando análisis sobre: {os.path.basename(latest_master)}")
            cmd = [
                sys.executable,
                os.path.join(BASE_DIR, 'Sentinel.py'),
                '--archivo', latest_master
            ]
            if skip_ai:
                cmd.append('--skip-ai')
            if model_name:
                cmd.extend(['--model', model_name])
            # Sentinel disparado directamente empieza en el 50% de progreso visual
            scan_status['progress'] = 50 
        
        try:
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True,
                cwd=BASE_DIR,
                bufsize=1,
                universal_newlines=True
            )
            current_scan_process = process
            
            line_count = 0
            for line in iter(process.stdout.readline, ''):
                if line:
                    line = line.strip()
                    scan_status['log'].append(line)
                    if len(scan_status['log']) > 300:
                        scan_status['log'] = scan_status['log'][-300:]
                    line_count += 1
                    
                    if 'INICIANDO FLUJO' in line:
                         scan_status['progress'] = 5
                         
                    # Update progress based on keywords
                    elif 'Procesando' in line or 'Buscando' in line:
                        scan_status['current_target'] = line
                        # Increment slowly during collection, cap at 45%
                        if scan_status['progress'] < 45:
                            scan_status['progress'] += 5
                            
                    elif 'Consolidando datos' in line:
                        scan_status['progress'] = 50
                        scan_status['message'] = "Consolidando resultados..."
                        
                    elif 'Archivo Maestro generado' in line:
                        scan_status['progress'] = 55
                        scan_status['message'] = "Iniciando análisis de inteligencia..."

                    elif '[AI_PROGRESS]' in line:
                        try:
                            # Format: [AI_PROGRESS] 10/100
                            parts = line.split(']')[1].strip().split('/')
                            current = int(parts[0])
                            total = int(parts[1])
                            if total > 0:
                                ai_pct = current / total
                                # Map 0%-100% of AI phase to 55%-80% of total bar (range of 25)
                                scan_status['progress'] = int(55 + (ai_pct * 25))
                                scan_status['message'] = f"Analizando con IA: {current}/{total} menciones..."
                        except:
                            pass
                        
                    elif 'Generando Dashboard Visual' in line:
                        scan_status['progress'] = 80
                        scan_status['message'] = "Generando visualizaciones..."
                        
                    elif 'Generando Timeline' in line:
                        scan_status['progress'] = 90
                        scan_status['message'] = "Finalizando reporte..."
                        
                    elif 'FLUJO COMPETITIVO COMPLETADO' in line:
                        scan_status['progress'] = 98
                        scan_status['message'] = "Completado"
                    
                    elif '[*]' in line:
                         # Small increment for generic info, cap based on current stage
                         if scan_status['progress'] < 50:
                             scan_status['progress'] = min(45, scan_status['progress'] + 1)
                    
                    # Update message
                    if 'Error' in line:
                        scan_status['message'] = f'Error: {line[:50]}'
                    elif 'Completado' in line or 'finalizado' in line.lower():
                        scan_status['message'] = 'Finalizando...'
            
            process.wait()
            scan_status['progress'] = 100
            scan_status['message'] = 'Escaneo completado'
            scan_status['log'].append('=== Escaneo completado ===')
            
        except Exception as e:
            scan_status['log'].append(f"Error: {str(e)}")
            scan_status['message'] = f'Error: {str(e)}'
        finally:
            current_scan_process = None
            scan_status['running'] = False
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({'status': 'started', 'message': 'Escaneo iniciado'})

@app.route('/api/scan/status')
def api_scan_status():
    """Get current scan status."""
    return jsonify({
        'running': scan_status['running'],
        'progress': scan_status['progress'],
        'current_target': scan_status['current_target'],
        'message': scan_status['message'],
        'log': scan_status['log'][-30:],  # Last 30 lines
        'started_at': scan_status['started_at']
    })

@app.route('/api/scan/cancel', methods=['POST'])
def api_cancel_scan():
    """Cancel the currently running scan."""
    global current_scan_process, scan_status
    if not scan_status['running'] or not current_scan_process:
        return jsonify({'success': False, 'message': 'No hay ningún escaneo activo para cancelar.'})
    try:
        current_scan_process.terminate()
        try:
            current_scan_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            current_scan_process.kill()
        scan_status['running'] = False
        scan_status['message'] = 'Escaneo cancelado por el usuario'
        scan_status['log'].append('=== Escaneo cancelado por el usuario ===')
        return jsonify({'success': True, 'message': 'Escaneo cancelado correctamente'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scans')
def api_scans():
    """Get list of available scans."""
    return jsonify(get_recent_scans())

@app.route('/api/data/<scan_name>/<csv_file>')
def api_csv_data(scan_name, csv_file):
    """Get CSV data as JSON."""
    data = load_csv_data(scan_name, csv_file)
    return jsonify(data)

@app.route('/api/explorer/<scan_name>')
def api_explorer_data(scan_name):
    """Get filtered data for explorer."""
    filters = {
        'sentiment': request.args.get('sentiment'),
        'source': request.args.get('source'),
        'entity': request.args.get('entity'),
        'risk': request.args.get('risk'),
        'category': request.args.get('category'),
        'type': request.args.get('type'),
        'search': request.args.get('search')
    }
    
    # History flag
    include_history = request.args.get('history', 'false').lower() == 'true'
    
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    data, filter_options = load_all_scan_data(scan_name, filters, include_history)
    
    # Calculate pagination
    total = len(data)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = data[start:end]
    
    return jsonify({
        'data': paginated_data,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page,
        'filter_options': filter_options
    })

@app.route('/reportes/<path:filename>')
def serve_report_file(filename):
    """Serve files securely from reportes directory."""
    safe_path = os.path.normpath(os.path.join(REPORTES_DIR, filename))
    if not safe_path.startswith(os.path.abspath(REPORTES_DIR)):
        abort(403)
    return send_from_directory(REPORTES_DIR, filename)

@app.route('/api/mention/action', methods=['POST'])
def mention_action():
    """Perform an action on a specific mention (delete, mark as noise, etc.)"""
    data = request.json
    scan_name = data.get('scan_name')
    file_name = data.get('_source_file')
    mention_id = data.get('id')
    action = data.get('action') # 'delete', 'ruido', 'positivo', 'negativo', 'neutro'

    if not all([scan_name, file_name, action]):
        return jsonify({'success': False, 'error': 'Faltan parámetros requeridos'}), 400

    path = os.path.join(REPORTES_DIR, scan_name, file_name)
    if not os.path.exists(path):
        # Try finding it in subdirectories
        found = False
        for root, dirs, files in os.walk(os.path.join(REPORTES_DIR, scan_name)):
            if file_name in files:
                path = os.path.join(root, file_name)
                found = True
                break
        if not found:
            return jsonify({'success': False, 'error': f'Archivo {file_name} no encontrado'}), 404

    try:
        df = pd.read_csv(path)
        
        # Find the row. Usually 'id' is unique within the file.
        if 'id' in df.columns and mention_id:
            mask = df['id'].astype(str) == str(mention_id)
        else:
            # Fallback to matching by comment snippet if ID is missing or not unique
            comment = data.get('comentario')
            if comment:
                mask = df['comentario'] == comment
            else:
                return jsonify({'success': False, 'error': 'No se puede identificar la mención de forma única'}), 400

        if not mask.any():
            return jsonify({'success': False, 'error': 'Mención no encontrada en el archivo'}), 404

        if action == 'delete':
            df = df[~mask]
        elif action in ['Positivo', 'Negativo', 'Neutro', 'Ruido']:
            # Find the sentiment column
            sent_col = next((c for c in ['Etiqueta', 'etiqueta', 'Sentiment', 'sentiment'] if c in df.columns), 'Etiqueta')
            df.loc[mask, sent_col] = action
            # Also update alerta status
            if 'Alerta' in df.columns:
                df.loc[mask, 'Alerta'] = 'SI' if action == 'Negativo' else 'NO'
        else:
            return jsonify({'success': False, 'error': f'Acción desconocida: {action}'}), 400

        df.to_csv(path, index=False)
        return jsonify({'success': True, 'message': f'Acción {action} realizada exitosamente'})

    except Exception as e:
        print(f"Error performing action {action}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Forensics Routes
@app.route('/forensics')
def forensics_dashboard():
    """Forensics dashboard page."""
    conn = sqlite3.connect(FORENSIC_DB)
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY started_at DESC")
    scans = c.fetchall()
    
    # JOIN to get Domain Authority
    c.execute("""
        SELECT b.id, b.url, b.target_url, b.domain, b.kri_score, b.status_code, b.language, b.context_excerpt, d.authority_score, b.kri_reasons 
        FROM backlinks b 
        LEFT JOIN domains d ON b.domain = d.domain 
        ORDER BY b.kri_score DESC LIMIT 50
    """)
    top_threats = c.fetchall()
    
    # Get Heatmap Data (All scores)
    c.execute("SELECT kri_score, url FROM backlinks")
    all_scores = c.fetchall()
    
    conn.close()
    
    # Process heatmap data
    heatmap_data = []
    risk_counts = {'toxic': 0, 'suspicious': 0, 'safe': 0}
    
    for score, url in all_scores:
        heatmap_data.append({'score': score, 'url': url})
        if score >= 70: risk_counts['toxic'] += 1
        elif score >= 30: risk_counts['suspicious'] += 1
        else: risk_counts['safe'] += 1
    
    # Format threat data for template
    threat_list = []
    for t in top_threats:
        try:
            reasons = json.loads(t[9]) if t[9] else []
        except:
            reasons = []
            
        threat_list.append({
            'id': t[0],
            'url': t[1],
            'target': t[2],
            'domain': t[3],
            'score': t[4],
            'status_code': t[5],
            'lang': t[6],
            'context': t[7] or "",
            'da': t[8] or 0,
            'reasons': reasons
        })
    
    scan_list = []
    for s in scans:
        scan_list.append({
            'id': s[0],
            'filename': s[1],
            'total': s[2],
            'processed': s[3],
            'started': s[4],
            'finished': s[5],
            'status': s[6]
        })
    
    return render_template('forensics.html', 
                           scans=scan_list, 
                           threats=threat_list, 
                           heatmap_data=heatmap_data,
                           risk_counts=risk_counts,
                           stats={'scan_name': ''},
                           recent_scans=get_recent_scans(),
                           selected_scan=None,
                           active_module='forensics')

@app.route('/forensics/settings')
def forensics_settings():
    """Forensics configuration page."""
    # Load config (defaults for now)
    config_path = os.path.join(CONFIG_DIR, 'forensics_config.json')
    config = {
        'toxic_keywords': ['casino', 'apuestas', 'bet', 'porn', 'sex', 'viagra', 'cryptocurrency', 'bitmex'],
        'toxic_threshold': 70,
        'suspicious_threshold': 30
    }
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except:
            pass
            
    return render_template('forensics_settings.html', 
                           config=config,
                           stats={'scan_name': ''},
                           recent_scans=get_recent_scans(),
                           selected_scan=None,
                           active_module='forensics')

@app.route('/api/forensics/settings', methods=['POST'])
def save_forensics_settings():
    """Saves forensics configuration to JSON."""
    data = request.json
    if not data:
        return jsonify({'success': False, 'error': 'No se proporcionaron datos'}), 400
        
    config_path = os.path.join(CONFIG_DIR, 'forensics_config.json')
    try:
        with open(config_path, 'w') as f:
            json.dump(data, f, indent=4)
        return jsonify({'success': True, 'message': 'Configuración guardada exitosamente'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/forensics/upload', methods=['POST'])
def upload_gsc():
    """Handles GSC CSV upload and starts background scan."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No se encontró la parte del archivo'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'Ningún archivo seleccionado'}), 400
        
    safe_name = secure_filename(file.filename)
    if not safe_name.lower().endswith('.csv'):
        return jsonify({'success': False, 'error': 'Formato no permitido (solo .csv)'}), 400

    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
    file.save(upload_path)
    
    # Start thread
    def run_scan():
        processor = ForensicProcessor()
        processor.process_scan(upload_path)
        
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({'success': True, 'message': 'Escaneo iniciado en segundo plano'})

@app.route('/api/forensics/check_link', methods=['POST'])
def check_link_status():
    """Real-time liveness check."""
    data = request.json
    url = data.get('url')
    if not url: return jsonify({'error': 'URL missing'}), 400
    
    processor = ForensicProcessor()
    status = processor.check_link_liveness(url)
    
    return jsonify({'status_code': status})

@app.route('/api/forensics/verify_all', methods=['POST'])
def verify_all_links():
    """Background job to check liveness of all links."""
    def run_check():
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        c.execute("SELECT url, id FROM backlinks")
        links = c.fetchall()
        conn.close()
        
        processor = ForensicProcessor()
        for url, link_id in links:
            code = processor.check_link_liveness(url)
            
            # Update DB
            conn = sqlite3.connect(FORENSIC_DB)
            c = conn.cursor()
            c.execute("UPDATE backlinks SET status_code = ? WHERE id = ?", (code, link_id))
            conn.commit()
            conn.close()
            
    thread = threading.Thread(target=run_check)
    thread.start()
    return jsonify({'success': True, 'message': 'Verificación masiva iniciada en segundo plano.'})

@app.route('/forensics/export')
def export_forensics_csv():
    """Export backlinks data to CSV."""
    def generate():
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        # JOIN to get Domain Authority
        c.execute("""
            SELECT b.url, b.domain, b.target_url, b.kri_score, b.status_code, b.context_excerpt, d.authority_score 
            FROM backlinks b 
            LEFT JOIN domains d ON b.domain = d.domain
        """)
        
        yield "URL,Dominio,Objetivo,KRI Score,Status Code,Contexto,Autoridad (DA)\n"
        
        while True:
            rows = c.fetchmany(100)
            if not rows: break
            for r in rows:
                # Clean strings for CSV
                url = str(r[0]).replace(',', '%2C')
                domain = str(r[1])
                target = str(r[2])
                kri = str(r[3])
                status = str(r[4])
                context = str(r[5] or "").replace('\n', ' ').replace(',', ';')
                da = str(r[6] or 0)
                
                yield f"{url},{domain},{target},{kri},{status},{context},{da}\n"
        
        conn.close()

    return Response(stream_with_context(generate()), mimetype='text/csv', headers={"Content-Disposition": "attachment; filename=backlinks_export.csv"})

@app.route('/api/forensics/search', methods=['POST'])
def forensics_search():
    """Executes Backlinker.py in background."""
    data = request.json
    domain = data.get('domain')
    entity = data.get('entity', 'Unknown')
    depth = data.get('depth', 1)
    
    if not domain:
        return jsonify({'success': False, 'error': 'Dominio requerido'}), 400
        
    def run_backlinker_job():
        try:
            # 1. Run Backlinker
            cmd = [
                sys.executable, "Backlinker.py",
                "--dominio", domain,
                "--entidad", entity,
                "--iterations", str(depth),
                "--num_results", "50"
            ]
            print(f"Running Backlinker: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)
            
            # 2. Find Output CSV
            # Backlinker logic: recoleccion/backlinks_{ENTIDAD}_{TIMESTAMP}.csv
            # We look for the most recent file matching the entity
            clean_entity = entity.replace(" ", "_")
            import glob
            files = glob.glob(f"recoleccion/backlinks_{clean_entity}_*.csv")
            if not files:
                print("No CSV found after Backlinker run.")
                return
                
            latest_file = max(files, key=os.path.getctime)
            print(f"Ingesting file: {latest_file}")
            
            # 3. Process with ForensicProcessor
            processor = ForensicProcessor(FORENSIC_DB)
            processor.process_scan(latest_file)
            
        except Exception as e:
            print(f"Error in background search job: {e}")

    thread = threading.Thread(target=run_backlinker_job)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Búsqueda iniciada en segundo plano.'})

@app.route('/api/forensics/status')
def forensics_status():
    """Returns status of active and recent scans."""
    try:
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        c.execute("SELECT id, filename, total_links, processed_links, status FROM scans ORDER BY started_at DESC LIMIT 5")
        rows = c.fetchall()
        conn.close()
        
        scans = [{
            'id': r[0],
            'filename': r[1],
            'total': r[2],
            'processed': r[3],
            'status': r[4],
            'progress': round((r[3]/r[2])*100, 1) if r[2] > 0 else 0
        } for r in rows]
        
        return jsonify({'success': True, 'scans': scans})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/forensics/scan/<scan_id>', methods=['DELETE'])
@login_required
def delete_forensic_scan(scan_id):
    """Deletes a forensic scan from the database."""
    try:
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Análisis eliminado correctamente'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# --- SPIDERFOOT MODULE ROUTES ---

@app.route('/spiderfoot')
def spiderfoot_dashboard():
    scans = get_spiderfoot_scans()
    return render_template('spiderfoot_dashboard.html', scans=scans, active_module='spiderfoot')

@app.route('/spiderfoot/upload', methods=['POST'])
def spiderfoot_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No se seleccionó ningún archivo'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'Nombre de archivo vacío'}), 400
    
    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.csv'):
        return jsonify({'success': False, 'error': 'Formato no soportado (solo .csv)'}), 400

    if os.path.exists(os.path.join(SPIDERFOOT_DIR, filename)):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name_root, ext = os.path.splitext(filename)
        filename = f"{name_root}_{timestamp}.csv"
        
    filepath = os.path.join(SPIDERFOOT_DIR, filename)
    file.save(filepath)
    return jsonify({'success': True, 'message': 'Archivo subido correctamente'})

@app.route('/spiderfoot/scan/<scan_name>')
def spiderfoot_scan(scan_name):
    filter_cat = request.args.get('category')
    
    # Correctly unpack 3 values
    parsed = parse_spiderfoot_data(scan_name)
    if not parsed or parsed[0] is None:
        return render_template('spiderfoot_scan.html', error="No se pudo cargar el archivo.", active_module='spiderfoot')
    
    stats, details, graph_data = parsed

    if filter_cat:
        # Show details for specific category
        cat_data = details.get(filter_cat, [])
        return render_template('spiderfoot_category.html', 
                             scan_name=scan_name, 
                             category=filter_cat, 
                             data=cat_data, 
                             active_module='spiderfoot')
    
    # Show Dashboard for Scan
    return render_template('spiderfoot_scan.html', 
                         scan_name=scan_name, 
                         stats=stats,
                         graph_data=graph_data,
                         active_module='spiderfoot')

@app.route('/spiderfoot/scan/<scan_name>/graph')
def spiderfoot_graph(scan_name):
    parsed = parse_spiderfoot_data(scan_name)
    if not parsed or parsed[0] is None:
        return render_template('spiderfoot_scan.html', error="No se pudo cargar el archivo.", active_module='spiderfoot')
    
    stats, details, graph_data = parsed
    return render_template('spiderfoot_graph.html', 
                         scan_name=scan_name,
                         graph_data=graph_data,
                         active_module='spiderfoot')

@app.route('/spiderfoot/delete/<scan_name>', methods=['POST'])
def spiderfoot_delete(scan_name):
    try:
        filepath = os.path.join(SPIDERFOOT_DIR, scan_name)
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Archivo no encontrado'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/spiderfoot/risk', methods=['POST'])
def save_spiderfoot_risk():
    try:
        data = request.json
        scan_name = data.get('scan_name')
        category = data.get('category')
        value = data.get('value')
        
        d = int(data.get('damage', 0))
        r = int(data.get('reproducibility', 0))
        e = int(data.get('exploitability', 0))
        a = int(data.get('affected_users', 0))
        disc = int(data.get('discoverability', 0))
        notes = data.get('notes', '')
        
        score, severity = calculate_dread_score(d, r, e, a, disc)
        finding_hash = get_finding_hash(category, value)
        
        conn = sqlite3.connect(FORENSIC_DB)
        c = conn.cursor()
        
        # Check if exists, update or insert
        c.execute("SELECT id FROM spiderfoot_risk WHERE scan_name=? AND finding_hash=?", (scan_name, finding_hash))
        existing = c.fetchone()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if existing:
            c.execute("""UPDATE spiderfoot_risk 
                         SET damage=?, reproducibility=?, exploitability=?, affected_users=?, discoverability=?, 
                             score=?, severity=?, notes=?, timestamp=?
                         WHERE id=?""", 
                      (d, r, e, a, disc, score, severity, notes, timestamp, existing[0]))
        else:
            c.execute("""INSERT INTO spiderfoot_risk 
                         (scan_name, finding_hash, category, value, damage, reproducibility, exploitability, affected_users, discoverability, score, severity, notes, timestamp)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                      (scan_name, finding_hash, category, value, d, r, e, a, disc, score, severity, notes, timestamp))
                      
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'score': score, 'severity': severity})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def compare_spiderfoot_scans(scan1_name, scan2_name):
    """
    Compare two scan files.
    Returns:
    - comparison: { category: { new: [], removed: [], common: [] } }
    """
    stats1, details1, _ = parse_spiderfoot_data(scan1_name)
    stats2, details2, _ = parse_spiderfoot_data(scan2_name)
    
    if not stats1 or not stats2:
        return None

    comparison = {}
    all_categories = set(stats1.keys()) | set(stats2.keys())
    
    for cat in all_categories:
        list1 = details1.get(cat, [])
        list2 = details2.get(cat, [])
        
        # Create sets of values for easy comparison
        set1 = {item['value'] for item in list1}
        set2 = {item['value'] for item in list2}
        
        new_items = set2 - set1
        removed_items = set1 - set2
        common_items = set1 & set2
        
        if new_items or removed_items:
            comparison[cat] = {
                'new': sorted(list(new_items)),
                'removed': sorted(list(removed_items)),
                'common_count': len(common_items)
            }
            
    return comparison

@app.route('/spiderfoot/compare', methods=['GET', 'POST'])
def spiderfoot_compare():
    if request.method == 'POST':
        scan1 = request.form.get('scan1')
        scan2 = request.form.get('scan2')
        
        if not scan1 or not scan2:
            return jsonify({'success': False, 'error': 'Seleccione dos escaneos'})
            
        comparison = compare_spiderfoot_scans(scan1, scan2)
        if comparison is None:
             return jsonify({'success': False, 'error': 'Error al procesar archivos'})
             
        return render_template('spiderfoot_compare.html', 
                             scan1=scan1, 
                             scan2=scan2, 
                             comparison=comparison, 
                             active_module='spiderfoot')
    
    # GET: Show selection form? Or just redirect
    return redirect(url_for('spiderfoot_dashboard'))

    # GET: Show selection form? Or just redirect
    return redirect(url_for('spiderfoot_dashboard'))

# --- REPORT GENERATION ROUTES ---

@app.route('/reports')
@login_required
def report_dashboard():
    sentiment_scans = get_recent_scans()
    spiderfoot_scans = get_spiderfoot_scans()
    
    # Get Forensics Scans (Backlinks)
    conn = sqlite3.connect(FORENSIC_DB)
    c = conn.cursor()
    c.execute("SELECT id, filename, started_at FROM scans ORDER BY started_at DESC")
    forensics_cases = [{'id': r[0], 'name': r[1], 'date': r[2].split('T')[0] if r[2] else 'N/A'} for r in c.fetchall()]
    conn.close()
    
    return render_template('reports.html', 
                         sentiment_scans=sentiment_scans,
                         spiderfoot_scans=spiderfoot_scans,
                         forensics_cases=forensics_cases,
                         active_module='reports')

@app.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    try:
        # 1. Gather Selections
        sentiment_scan = request.form.get('sentiment_scan')
        spiderfoot_scan = request.form.get('spiderfoot_scan')
        forensics_case_id = request.form.get('forensics_case')
        sentiment_objective = request.form.get('sentiment_objective', '')
        spiderfoot_objective = request.form.get('spiderfoot_objective', '')
        forensics_objective = request.form.get('forensics_objective', '')
        
        # Checkbox Options
        options = {
            'sentiment_summary': 'sentiment_summary' in request.form,
            'sentiment_graphs': 'sentiment_graphs' in request.form,
            'sentiment_top': 'sentiment_top' in request.form,
            'spiderfoot_summary': 'spiderfoot_summary' in request.form,
            'spiderfoot_critical': 'spiderfoot_critical' in request.form,
            'forensics_summary': 'forensics_summary' in request.form,
            'forensics_evidence': 'forensics_evidence' in request.form
        }

        report_data = {
            'generated_at': datetime.now().strftime("%d/%m/%Y %H:%M"),
            'report_id': f"RPT-{datetime.now().strftime('%Y%m%d-%H%M')}",
            'sections': [],
            'options': options
        }
        
        # 2. Process SpyderFoot
        if spiderfoot_scan:
            stats, details, _ = parse_spiderfoot_data(spiderfoot_scan)
            
            # Calculate Risk Score
            total_findings = sum(stats.values())
            high_risk_count = 0
            critical_findings = []
            category_breakdown = []
            
            # Process ALL categories for breakdown
            for cat, items in details.items():
                cat_total = len(items)
                cat_high = 0
                cat_med = 0
                cat_low = 0
                
                for item in items:
                    risk = item.get('risk', 'INFO')
                    if risk in ['HIGH', 'CRITICAL', 'CRÍTICO']:
                        cat_high += 1
                        high_risk_count += 1
                        # Add to critical list if option selected
                        if options['spiderfoot_critical'] and len(critical_findings) < 50:
                             critical_findings.append({
                                'category': cat,
                                'value': item['value'],
                                'severity': risk,
                                'module': ', '.join(list(item['modules'])[:2])
                            })
                    elif risk in ['MEDIUM', 'ALTO', 'MEDIA']:
                        cat_med += 1
                    else:
                        cat_low += 1
                
                category_breakdown.append({
                    'name': cat,
                    'total': cat_total,
                    'high': cat_high,
                    'medium': cat_med,
                    'low': cat_low
                })
            
            # Sort categories by risk (High desc, then Total desc)
            category_breakdown.sort(key=lambda x: (x['high'], x['total']), reverse=True)

            report_data['spiderfoot'] = {
                'scan_name': spiderfoot_scan,
                'total_findings': total_findings,
                'high_risk_count': high_risk_count,
                'stats': stats,
                'critical_findings': critical_findings,
                'categories': category_breakdown,
                'objective': spiderfoot_objective
            }
            report_data['sections'].append('spiderfoot')

        # 3. Process Sentiment
        if sentiment_scan:
             # Get Stats
             stats = get_stats_for_scan(sentiment_scan)
             
             top_mentions = []
             if options['sentiment_top']:
                 try:
                     df, _ = load_all_scan_data(sentiment_scan)
                     if not df.empty:
                         # Prioritize: High negative sentiment OR High Risk words
                         # We'll filter for negative sentiment > 0.8 or Risk keywords
                         # For simplicity, sort by negative score
                         if 'Distilroberta_score_negative' in df.columns:
                             df_risk = df.sort_values(by='Distilroberta_score_negative', ascending=False).head(10)
                             top_mentions = df_risk[['text', 'Distilroberta_score_negative', 'source']].to_dict('records')
                         else:
                             top_mentions = df.head(10).to_dict('records')
                 except Exception as e:
                     print(f"Error loading top mentions: {e}")

             report_data['sentiment'] = {
                'scan_name': sentiment_scan,
                'stats': stats,
                'top_mentions': top_mentions,
                'objective': sentiment_objective
            }
             report_data['sections'].append('sentiment')

        # 4. Process Forensics (Backlinks)
        if forensics_case_id:
             conn = sqlite3.connect(FORENSIC_DB)
             c = conn.cursor()
             c.execute("SELECT filename, started_at, total_links, status FROM scans WHERE id=?", (forensics_case_id,))
             scan_data = c.fetchone()
             
             # Obtenemos estadísticas generales de riesgo
             c.execute("SELECT kri_score FROM backlinks")
             all_scores = c.fetchall()
             risk_counts = {'toxic': 0, 'suspicious': 0, 'safe': 0}
             for score, in all_scores:
                 if score >= 70: risk_counts['toxic'] += 1
                 elif score >= 30: risk_counts['suspicious'] += 1
                 else: risk_counts['safe'] += 1

             top_threats = []
             if options['forensics_evidence']:
                 c.execute("""
                    SELECT b.url, b.domain, b.kri_score, b.status_code, d.authority_score, b.context_excerpt, b.kri_reasons
                    FROM backlinks b 
                    LEFT JOIN domains d ON b.domain = d.domain 
                    ORDER BY b.kri_score DESC LIMIT 10
                 """)
                 for t in c.fetchall():
                     try:
                         reasons = json.loads(t[6]) if t[6] else []
                     except:
                         reasons = []
                         
                     top_threats.append({
                         'url': t[0],
                         'domain': t[1],
                         'score': t[2],
                         'status_code': t[3],
                         'da': t[4] or 0,
                         'context': t[5] or '',
                         'reasons': reasons
                     })

             conn.close()
             
             if scan_data:
                 report_data['forensics'] = {
                     'filename': scan_data[0],
                     'date': scan_data[1].split('T')[0] if scan_data[1] else 'N/A',
                     'total_links': scan_data[2],
                     'scan_status': scan_data[3],
                     'counts': risk_counts,
                     'threats': top_threats,
                     'objective': forensics_objective
                 }
                 report_data['sections'].append('forensics')

        # Render HTML template as string
        html_content = render_template('report_template.html', **report_data)
        
        # Generate PDF using WeasyPrint
        from weasyprint import HTML
        base_url = request.host_url if request else None
        pdf_bytes = HTML(string=html_content, base_url=base_url).write_pdf()
        
        # Create Response
        response = make_response(pdf_bytes)
        response.headers['Content-Type'] = 'application/pdf'
        # Use 'attachment' to force download, or 'inline' to view in browser
        response.headers['Content-Disposition'] = f'inline; filename=reporte_{report_data["report_id"]}.pdf'
        
        return response

    except Exception as e:
        return f"Error generando reporte: {str(e)}", 500

if __name__ == '__main__':
    print("=" * 50)
    print("Brand Sentiment Dashboard")
    print("=" * 50)
    print(f"Starting server at https://localhost:5000 (TLS Enabled)")
    
    # Check for SSL certs
    cert_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cert.pem')
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key.pem')
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=(cert_file, key_file))
    else:
        print("Warning: SSL certificates not found. Running in HTTP mode.")
        app.run(debug=True, host='0.0.0.0', port=5000)
