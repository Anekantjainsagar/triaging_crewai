import os
import requests
from dotenv import load_dotenv

load_dotenv()

class IPReputationChecker:
    def __init__(self):
        self.abuse_db_key = os.getenv("ABUSE_DB_KEY")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abstract_key = os.getenv("ABSTRACT_API_KEY")
    
    def check_abuseipdb(self, ip_address):
        """Check IP reputation using AbuseIPDB"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuse_db_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'source': 'AbuseIPDB',
                    'abuse_confidence': data.get('data', {}).get('abuseConfidencePercentage', 0),
                    'is_public': data.get('data', {}).get('isPublic', False),
                    'usage_type': data.get('data', {}).get('usageType', 'Unknown'),
                    'isp': data.get('data', {}).get('isp', 'Unknown'),
                    'country': data.get('data', {}).get('countryCode', 'Unknown'),
                    'is_tor': data.get('data', {}).get('isTor', False),
                    'total_reports': data.get('data', {}).get('totalReports', 0)
                }
        except Exception as e:
            return {'source': 'AbuseIPDB', 'error': str(e)}
    
    def check_virustotal(self, ip_address):
        """Check IP reputation using VirusTotal"""
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.virustotal_key,
                'ip': ip_address
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                detected_urls = data.get('detected_urls', [])
                detected_samples = data.get('detected_downloaded_samples', [])
                
                return {
                    'source': 'VirusTotal',
                    'malicious_urls': len(detected_urls),
                    'malicious_samples': len(detected_samples),
                    'asn': data.get('asn', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'owner': data.get('as_owner', 'Unknown'),
                    'reputation': 'malicious' if (len(detected_urls) > 0 or len(detected_samples) > 0) else 'clean'
                }
        except Exception as e:
            return {'source': 'VirusTotal', 'error': str(e)}
    
    def check_abstract_api(self, ip_address):
        """Check IP geolocation and VPN/Proxy status using Abstract API"""
        try:
            url = f"https://ipgeolocation.abstractapi.com/v1/"
            params = {
                'api_key': self.abstract_key,
                'ip_address': ip_address
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Check VPN/Proxy status
                security = data.get('security', {})
                
                return {
                    'source': 'Abstract API',
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'timezone': data.get('timezone', {}).get('name', 'Unknown'),
                    'isp': data.get('connection', {}).get('isp', 'Unknown'),
                    'connection_type': data.get('connection', {}).get('connection_type', 'Unknown'),
                    'is_vpn': security.get('is_vpn', False),
                    'is_proxy': security.get('is_proxy', False),
                    'is_tor': security.get('is_tor', False),
                    'is_relay': security.get('is_relay', False),
                    'threat_types': security.get('threat_types', [])
                }
            else:
                return {'source': 'Abstract API', 'error': f'HTTP {response.status_code}: {response.text}'}
        except Exception as e:
            return {'source': 'Abstract API', 'error': str(e)}
    
    def get_comprehensive_reputation(self, ip_address):
        """Get comprehensive IP reputation from all sources"""
        if not ip_address or ip_address == 'Unknown':
            return {'error': 'Invalid IP address'}
        
        results = {}
        
        # Check all three sources
        results['abuseipdb'] = self.check_abuseipdb(ip_address) or {'source': 'AbuseIPDB', 'error': 'No response'}
        results['virustotal'] = self.check_virustotal(ip_address) or {'source': 'VirusTotal', 'error': 'No response'}
        results['abstract'] = self.check_abstract_api(ip_address) or {'source': 'Abstract API', 'error': 'No response'}
        
        # Calculate overall risk score
        risk_score = 0
        risk_factors = []
        
        # AbuseIPDB scoring
        if 'abuseipdb' in results and 'abuse_confidence' in results['abuseipdb']:
            abuse_conf = results['abuseipdb']['abuse_confidence']
            if abuse_conf > 75:
                risk_score += 40
                risk_factors.append(f"High abuse confidence ({abuse_conf}%)")
            elif abuse_conf > 25:
                risk_score += 20
                risk_factors.append(f"Medium abuse confidence ({abuse_conf}%)")
        
        # VirusTotal scoring
        if 'virustotal' in results and 'malicious_urls' in results['virustotal']:
            malicious = results['virustotal']['malicious_urls'] + results['virustotal']['malicious_samples']
            if malicious > 5:
                risk_score += 30
                risk_factors.append(f"Multiple malicious detections ({malicious})")
            elif malicious > 0:
                risk_score += 15
                risk_factors.append(f"Some malicious detections ({malicious})")
        
        # Abstract API scoring
        if 'abstract' in results and 'is_vpn' in results['abstract']:
            if results['abstract']['is_vpn']:
                risk_score += 15
                risk_factors.append("VPN detected")
            if results['abstract']['is_proxy']:
                risk_score += 15
                risk_factors.append("Proxy detected")
            if results['abstract']['is_tor']:
                risk_score += 25
                risk_factors.append("Tor exit node")
        
        # Determine overall reputation
        if risk_score >= 50:
            reputation = "HIGH_RISK"
        elif risk_score >= 25:
            reputation = "MEDIUM_RISK"
        elif risk_score > 0:
            reputation = "LOW_RISK"
        else:
            reputation = "CLEAN"
        
        results['summary'] = {
            'ip_address': ip_address,
            'overall_reputation': reputation,
            'risk_score': min(risk_score, 100),
            'risk_factors': risk_factors,
            'is_public': results.get('abuseipdb', {}).get('is_public', True),
            'is_vpn_proxy_tor': any([
                results.get('abstract', {}).get('is_vpn', False),
                results.get('abstract', {}).get('is_proxy', False),
                results.get('abstract', {}).get('is_tor', False),
                results.get('abuseipdb', {}).get('is_tor', False)
            ])
        }
        
        return results