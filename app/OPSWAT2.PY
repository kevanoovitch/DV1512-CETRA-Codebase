import requests
import time
import json

METADEFENDER_URL = "https://api.metadefender.com/v4" 
API_KEY = "d4a3a7c0acb3ad5b5e2b088301cf1ea3"


def upload_file_for_scan(file_path):
    """
    Laddar upp en fil till MetaDefender Core och initierar skanning.

    Returnerar data_id om uppladdningen lyckas.
    """
    upload_endpoint = f"{METADEFENDER_URL}/file"
    headers = {
        'apikey': API_KEY,
        'Content-Type': 'application/octet-stream'
    }

    try:
        with open(file_path, 'rb') as f:
            print(f"Laddar upp fil: {file_path}...")
            response = requests.post(upload_endpoint, headers=headers, data=f)
            response.raise_for_status()

        result = response.json()
        data_id = result.get('data_id')
        
        if data_id:
            print(f"Uppladdning lyckades. Data ID: {data_id}")
            return data_id
        else:
            print("Fel: Data ID saknas i uppladdningssvaret.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Fel vid uppladdning eller anslutning: {e}")
        return None


def poll_and_get_results(data_id):
    """
    Pollar MetaDefender Core med data_id tills skanningen är klar (100%).

    Returnerar hela JSON-svaret.
    """
    result_endpoint = f"{METADEFENDER_URL}/file/{data_id}"
    headers = {'apikey': API_KEY}
    
    while True:
        try:
            response = requests.get(result_endpoint, headers=headers)
            response.raise_for_status()
            scan_report = response.json()

            progress = scan_report.get('scan_results', {}).get('progress_percentage', 0)
            print(f"Skanningsstatus för {data_id}: {progress}%")

            if progress == 100:
                print("Skanningen är klar.")
                return scan_report
            
            time.sleep(2) 

        except requests.exceptions.RequestException as e:
            print(f"Fel vid hämtning av resultat: {e}")
            return None

def main_metadefender_interface(file_to_scan):
    """
    Huvudgränssnittsfunktion som hanterar hela arbetsflödet.
    """
    
    data_id = upload_file_for_scan(file_to_scan)
    
    if not data_id:
        return "Processen misslyckades vid uppladdning."

    full_report = poll_and_get_results(data_id)
    
    if not full_report:
        return f"Processen misslyckades vid hämtning av resultat för ID: {data_id}."

    extracted_data = extract_report_values(data_id, full_report)

    return format_extracted_data(extracted_data)

def extract_report_values(data_id, full_report):
    """Extraherar de begärda fälten från den fullständiga JSON-rapporten."""
    
    id_val = data_id

    manifest_val = {
        "overall_verdict": full_report.get('scan_results', {}).get('scan_all_result_a', 'N/A'),
        "file_type": full_report.get('file_info', {}).get('file_type', 'N/A'),
        "hashes": {
            "md5": full_report.get('file_info', {}).get('md5', 'N/A'),
            "sha256": full_report.get('file_info', {}).get('sha256', 'N/A')
        }
    }
    
    vulnerabilities_val = full_report.get('vulnerability_info', 'Inte tillgänglig/skannad')

    signatures_val = [
        f"{motor}: {detaljer.get('threat_found', 'Ren/Ingen')}" 
        for motor, detaljer in full_report.get('scan_results', {}).get('scan_details', {}).items() 
        if detaljer.get('threat_found') # Filtrera bort tomma hot
    ]
    if not signatures_val:
        signatures_val = ["Inga signaturer (hot) upptäcktes"]

    urls_val = full_report.get('url_analysis_info', 'Inte tillgänglig/skannad') 

    analysis_val = full_report.get('scan_results', {}).get('scan_details', 'N/A')

    return {
        "ID": id_val,
        "Manifest": manifest_val,
        "Vulnerabilities": vulnerabilities_val,
        "Signatures": signatures_val,
        "URLs": urls_val,
        "Analysis": analysis_val
    }

def format_extracted_data(data):
    """Formaterar de extraherade värdena till en läsbar text."""
    
    output = []
    
    output.append("--- MetaDefender API-Returvärden ---")
    output.append(f"ID: {data['ID']}")
    output.append("-" * 30)

    output.append("\n### Manifest (Översikt)")
    output.append(f"Övergripande utslag: **{data['Manifest']['overall_verdict']}**")
    output.append(f"Filtyp: {data['Manifest']['file_type']}")
    output.append(f"MD5 Hash: {data['Manifest']['hashes']['md5']}")
    
    output.append("\n### Signaturer (Upptäckta hot)")
    for signature in data['Signatures']:
        output.append(f"- {signature}")
        
    output.append("\n### Sårbarheter (Vulnerabilities)")
    if isinstance(data['Vulnerabilities'], dict) and data['Vulnerabilities']:
         output.append(json.dumps(data['Vulnerabilities'], indent=2))
    else:
        output.append(str(data['Vulnerabilities']))

    output.append("\n### URL:er (URLs)")
    if isinstance(data['URLs'], dict) and data['URLs']:
         output.append(json.dumps(data['URLs'], indent=2))
    else:
        output.append(str(data['URLs']))

    output.append("\n### Fullständig Analys (scan_details)")
    output.append(json.dumps(data['Analysis'], indent=2))
    
    output.append("-----------------------------------")
    
    return "\n".join(output)