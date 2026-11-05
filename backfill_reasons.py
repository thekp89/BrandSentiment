import sqlite3
import json

def backfill_reasons():
    conn = sqlite3.connect('fenix.db')
    c = conn.cursor()
    c.execute("SELECT id, url, domain, status_code, kri_score FROM backlinks WHERE kri_reasons IS NULL OR kri_reasons = '[]' OR kri_reasons = ''")
    rows = c.fetchall()
    
    updated = 0
    for row in rows:
        b_id, url, domain, status_code, kri_score = row
        reasons = []
        score_accounted = 0
        
        if status_code == 0:
            reasons.append("Fallo de conexión o Dominio Inexistente (+80)")
            score_accounted += 80
        elif status_code >= 400:
            reasons.append(f"Estado HTTP {status_code} sospechoso (+20)")
            score_accounted += 20
            
        bad_tlds = ['-free.', '.top', '.xyz', '.online', '.site']
        matched_tld = [bad for bad in bad_tlds if domain and bad in domain]
        if matched_tld:
            reasons.append(f"Dominio de baja reputación: {matched_tld[0]} (+10)")
            score_accounted += 10
            
        remaining_score = kri_score - score_accounted
        if remaining_score > 0:
            if remaining_score % 15 == 0:
                reasons.append(f"Palabras tóxicas detectadas en el contenido (+{remaining_score})")
            else:
                reasons.append(f"Palabras tóxicas u otros factores (+{remaining_score})")
                
        if kri_score == 0:
            reasons.append("Sin indicadores de riesgo negativos")
            
        c.execute("UPDATE backlinks SET kri_reasons = ? WHERE id = ?", (json.dumps(reasons), b_id))
        updated += 1
        
    conn.commit()
    conn.close()
    print(f"Updated {updated} backlinks with retroactively calculated reasons.")

if __name__ == '__main__':
    backfill_reasons()
