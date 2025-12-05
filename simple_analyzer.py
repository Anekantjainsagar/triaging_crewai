import os
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
from ip_reputation import IPReputationChecker
from azure.identity import DefaultAzureCredential
from crewai import Agent, Task, Crew, Process, LLM

load_dotenv()

# Groq API Key Rotation System
class GroqKeyManager:
    def __init__(self):
        # Load all available Groq API keys
        self.api_keys = []
        
        # First, add the main GROQ_API_KEY
        main_key = os.getenv("GROQ_API_KEY")
        if main_key:
            self.api_keys.append(main_key)
        
        # Then add numbered keys (GROQ_API_KEY1, GROQ_API_KEY2, etc.)
        key_index = 1
        while True:
            key = os.getenv(f"GROQ_API_KEY{key_index}")
            if key:
                self.api_keys.append(key)
                key_index += 1
            else:
                break
        
        if not self.api_keys:
            raise ValueError("No Groq API keys found. Set GROQ_API_KEY or GROQ_API_KEY_1, GROQ_API_KEY_2, etc.")
        
        self.current_key_index = 0
        print(f"🔑 Loaded {len(self.api_keys)} Groq API keys for rotation")
        self.set_current_key()
    
    def set_current_key(self):
        """Set the current API key in environment"""
        current_key = self.api_keys[self.current_key_index]
        os.environ["GROQ_API_KEY"] = current_key
        print(f"🔄 Using API key #{self.current_key_index + 1}/{len(self.api_keys)}")
    
    def rotate_key(self):
        """Rotate to the next API key"""
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        self.set_current_key()
        return self.api_keys[self.current_key_index]

# Initialize key manager
key_manager = GroqKeyManager()

# Set environment variables for CrewAI LLM
os.environ["CREWAI_LLM_PROVIDER"] = "groq"
os.environ["CREWAI_LLM_MODEL"] = "llama-3.1-8b-instant"

def execute_kql_query(query):
    """Execute KQL query against Azure Sentinel workspace"""
    try:
        workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
        credential = DefaultAzureCredential()
        token = credential.get_token("https://api.loganalytics.io/.default").token
        
        url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body = {"query": query}
        
        response = requests.post(url, headers=headers, json=body)
        
        if response.status_code == 200:
            results = response.json()
            return results
        else:
            return {"error": f"Query failed: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": f"Error executing query: {str(e)}"}

class CrewAIAnalyzer:
    def __init__(self):
        self.query_cache = {}
        self.key_manager = key_manager
        self.agents = self._create_agents()
        self.ip_checker = IPReputationChecker()
        self.max_retries = len(key_manager.api_keys)
        
    def _create_agents(self):
        # Configure Groq LLM with current API key
        llm = LLM(
            model="groq/llama-3.1-8b-instant",
            api_key=os.getenv("GROQ_API_KEY")
        )
        
        kql_specialist = Agent(
            role='Azure Sentinel KQL Query Architect & Threat Intelligence Specialist',
            goal='''Design and execute sophisticated KQL queries that dynamically adapt to security alert characteristics, risk profiles, and threat landscapes. Generate multi-layered investigation queries that correlate authentication patterns, network behaviors, application usage, and temporal anomalies to provide comprehensive threat context. Optimize query performance while ensuring maximum detection coverage across Azure Sentinel workspaces and minimize computational overhead.''',
            backstory='''You are Dr. Sarah Chen, a renowned cybersecurity expert with 15+ years of specialized experience in Azure Sentinel architecture and KQL query optimization. You hold a Ph.D. in Computer Science with a focus on Security Analytics and are a Microsoft MVP for Azure Security. 
            
            Your expertise spans:
            • Advanced KQL query construction for complex threat hunting scenarios
            • Azure Sentinel workspace optimization and log analytics performance tuning
            • Behavioral analytics and user entity behavior analytics (UEBA) implementation
            • Threat intelligence integration and IOC correlation techniques
            • Machine learning-assisted anomaly detection in security logs
            • Cross-platform log correlation (Azure AD, Office 365, Windows Security Events)
            
            You've architected security monitoring solutions for Fortune 500 companies and government agencies, successfully detecting advanced persistent threats (APTs) that evaded traditional security tools. Your KQL queries have been featured in Microsoft's official threat hunting guides and you regularly speak at security conferences about advanced analytics techniques.
            
            Your approach is methodical and data-driven: you analyze alert metadata to determine optimal query strategies, consider performance implications of complex joins, and design queries that reveal both direct indicators and subtle behavioral patterns. You're known for creating "living queries" that adapt their scope and depth based on initial findings, progressively narrowing down to the most relevant security events.''',
            llm=llm,
            verbose=False
        )
        
        security_analyst = Agent(
            role='Senior SOC Analyst & Incident Response Specialist',
            goal='''Conduct comprehensive security alert analysis by synthesizing KQL investigation results, threat intelligence data, IP reputation analysis, and behavioral patterns to make definitive true/false positive determinations. Provide actionable incident response recommendations with detailed forensic context and risk assessment. Ensure accurate alert classification that minimizes analyst fatigue while maintaining high security posture.''',
            backstory='''You are Marcus Rodriguez, a veteran Security Operations Center (SOC) analyst with 12+ years of hands-on experience in enterprise security incident response and threat analysis. You hold CISSP, GCIH, and GCFA certifications and have led incident response teams at major financial institutions and healthcare organizations.
            
            Your specialized expertise includes:
            • Advanced threat analysis and attack pattern recognition across MITRE ATT&CK framework
            • Identity and access management (IAM) security analysis and privilege escalation detection
            • Network forensics and lateral movement investigation techniques
            • Malware analysis and indicators of compromise (IOC) correlation
            • Risk-based security assessment and business impact analysis
            • Insider threat detection and behavioral anomaly analysis
            • Compliance frameworks (SOX, HIPAA, PCI-DSS) and regulatory incident reporting
            
            You've successfully investigated over 10,000 security incidents, maintaining a 97% accuracy rate in true/false positive classification. Your analytical approach combines technical forensics with business context understanding - you don't just identify threats, but assess their potential impact and provide prioritized response strategies.
            
            You're particularly skilled at:
            • Correlating seemingly unrelated security events to identify sophisticated attack campaigns
            • Distinguishing between legitimate business activities and malicious behaviors
            • Analyzing authentication anomalies in complex hybrid cloud environments
            • Providing clear, actionable recommendations that balance security needs with operational requirements
            • Mentoring junior analysts and developing standard operating procedures for incident response
            
            Your decision-making process is thorough yet efficient: you systematically evaluate all available evidence, consider alternative explanations for suspicious activities, and provide confidence levels for your assessments. You understand that false positives waste valuable resources while false negatives can lead to security breaches.''',
            llm=llm,
            verbose=False
        )
        
        threat_hunter = Agent(
            role='Elite Threat Hunter & Advanced Persistent Threat (APT) Specialist',
            goal='''Conduct proactive threat hunting by analyzing subtle indicators, behavioral anomalies, and attack patterns that traditional security tools might miss. Investigate sophisticated threats including insider risks, advanced persistent threats, and zero-day exploits. Provide deep contextual analysis of security events by correlating multiple data sources and identifying attack progression stages. Develop threat hypotheses and validate them through systematic investigation techniques.''',
            backstory='''You are Alex Thompson, an elite threat hunter with 14+ years of experience specializing in advanced persistent threats (APTs), nation-state actors, and sophisticated cybercriminal organizations. You hold advanced certifications including SANS FOR508, GCTI, and GNFA, and have worked with government agencies and critical infrastructure organizations.
            
            Your specialized capabilities include:
            • Advanced persistent threat (APT) campaign analysis and attribution techniques
            • Behavioral analytics and machine learning-assisted anomaly detection
            • Digital forensics and incident reconstruction across complex enterprise environments
            • Threat intelligence analysis and strategic threat landscape assessment
            • Insider threat psychology and behavioral pattern analysis
            • Zero-day exploit identification and novel attack technique discovery
            • Cross-platform attack correlation (Windows, Linux, cloud environments)
            • Adversary tactics, techniques, and procedures (TTPs) mapping to MITRE ATT&CK
            
            Your hunting methodology is based on hypothesis-driven investigation:
            • You develop threat scenarios based on current intelligence and environmental factors
            • You design custom detection logic to identify subtle indicators of compromise
            • You correlate low-fidelity signals across multiple data sources to reveal hidden threats
            • You analyze attacker dwell time and lateral movement patterns
            • You assess the sophistication level and potential attribution of threat actors
            
            You've successfully identified and neutralized several APT campaigns that had remained undetected for months, including:
            • A sophisticated supply chain attack targeting financial institutions
            • An insider threat involving privileged access abuse in a healthcare organization
            • A nation-state actor conducting long-term espionage in a defense contractor
            
            Your analytical approach combines technical expertise with strategic thinking: you don't just identify individual threats, but understand their broader context within ongoing campaigns and threat landscapes. You excel at finding the "needle in the haystack" - those subtle anomalies that indicate sophisticated adversaries operating below the radar of traditional security controls.
            
            You're known for your ability to think like an attacker, anticipating their next moves and identifying defensive gaps before they can be exploited.''',
            llm=llm,
            verbose=False
        )
        
        return {
            'kql_specialist': kql_specialist,
            'security_analyst': security_analyst,
            'threat_hunter': threat_hunter
        }
        
    def generate_dynamic_kql_queries(self, alert_data):
        """Generate KQL queries dynamically based on alert data requirements"""
        user_email = alert_data.get('user_principal_name', '')
        ip_address = alert_data.get('locations', [{}])[0].get('ip_address', '')
        risk_factors = alert_data.get('risk_factors', [])
        risk_score = alert_data.get('risk_score', 0)
        applications = [app.get('app_name') for app in alert_data.get('applications', [])]
        
        # Use actual incident timestamp ±1 day for pattern analysis
        incident_time = alert_data.get('locations', [{}])[0].get('timestamp', '')
        if incident_time:
            from datetime import datetime, timedelta
            try:
                incident_dt = datetime.fromisoformat(incident_time.replace('Z', '+00:00'))
                start_time = (incident_dt - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                end_time = (incident_dt + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                time_filter = f"TimeGenerated between (datetime('{start_time}') .. datetime('{end_time}'))"
            except:
                time_filter = "TimeGenerated >= ago(2d)"
        else:
            time_filter = "TimeGenerated >= ago(2d)"
        
        queries = []
        
        # Query 1: User authentication patterns
        base_query = f"SigninLogs | where UserPrincipalName == '{user_email}' | where {time_filter}"
        
        if 'Unfamiliar sign-in properties' in risk_factors:
            base_query += " | where RiskDetail != 'none'"
        if 'Anonymous IP address' in risk_factors:
            base_query += " | where NetworkLocationDetails has 'anonymousProxy'"
        
        queries.append(base_query + " | summarize count() by AppDisplayName, IPAddress, bin(TimeGenerated, 1h) | order by TimeGenerated desc | limit 50")
        
        # Query 2: IP-based analysis
        if ip_address and ip_address != 'Unknown':
            ip_query = f"SigninLogs | where IPAddress == '{ip_address}' | where {time_filter}"
            
            if applications:
                app_filter = "' or AppDisplayName == '".join(applications)
                ip_query += f" | where AppDisplayName == '{app_filter}'"
            
            queries.append(ip_query + " | summarize count() by UserPrincipalName, AppDisplayName, bin(TimeGenerated, 1h) | order by TimeGenerated desc | limit 30")
        
        # Query 3: Audit logs (skip for guest users)
        user_type = alert_data.get('user_type', '')
        if user_type != 'Guest':
            audit_query = f"AuditLogs | where InitiatedBy.user.userPrincipalName == '{user_email}' | where {time_filter}"
            
            if risk_score >= 5:
                audit_query += " | where Category in ('RoleManagement', 'UserManagement', 'ApplicationManagement')"
            
            queries.append(audit_query + " | summarize count() by OperationName, bin(TimeGenerated, 1h) | order by TimeGenerated desc | limit 20")
        
        return queries
    
    def investigate_with_kql(self, alert_data):
        """Execute KQL queries with caching to avoid redundant calls"""
        user_email = alert_data.get('user_principal_name', '')
        ip_address = alert_data.get('locations', [{}])[0].get('ip_address', '')
        
        # Create cache key
        cache_key = f"{user_email}_{ip_address}"
        
        # Check cache first
        if cache_key in self.query_cache:
            print(f"  Using cached investigation results for {user_email}")
            return self.query_cache[cache_key]
        
        # Execute queries only if not cached
        queries = self.generate_dynamic_kql_queries(alert_data)
        investigation_results = {}
        
        for i, query in enumerate(queries):
            print(f"  Executing KQL Query {i+1}/{len(queries)}...")
            result = execute_kql_query(query)
            investigation_results[f"query_{i+1}"] = result
        
        # IP reputation check
        if ip_address and ip_address != 'Unknown':
            print(f"  Checking IP reputation for {ip_address}...")
            ip_reputation = self.ip_checker.get_comprehensive_reputation(ip_address)
            investigation_results['ip_reputation'] = ip_reputation
        
        # Cache results
        self.query_cache[cache_key] = investigation_results
        return investigation_results
      
    def analyze_alert_with_crew(self, alert_data):
        """CrewAI-powered analysis with all specialized agents and API key rotation"""
        
        for attempt in range(self.max_retries):
            try:
                # Recreate agents with current API key
                self.agents = self._create_agents()
                
                # Execute KQL investigation once
                kql_results = self.investigate_with_kql(alert_data)
                
                # Count actual queries executed
                query_count = len([k for k in kql_results.keys() if k.startswith('query_') and not k.endswith('_sql')])
                
                # Extract key findings from investigation
                findings_summary = []
                for i in range(1, query_count + 1):
                    query_result = kql_results.get(f'query_{i}', {})
                    if isinstance(query_result, dict) and 'tables' in query_result:
                        row_count = len(query_result['tables'][0].get('rows', [])) if query_result['tables'] else 0
                        findings_summary.append(f"Query {i}: {row_count} records")
                
                ip_reputation = kql_results.get('ip_reputation', {})
                ip_threat_score = 0
                if isinstance(ip_reputation, dict):
                    ip_threat_score = ip_reputation.get('threat_score', 0)
                
                # Classification task with actual data
                classification_task = Task(
                    description=f"""Analyze security alert and provide a definitive classification:
                    
                    User: {alert_data.get('user_principal_name')}
                    Risk Score: {alert_data.get('risk_score')}/10
                    Risk Factors: {alert_data.get('risk_factors')}
                    IP: {alert_data.get('locations', [{}])[0].get('ip_address', 'Unknown')}
                    
                    Investigation Results:
                    - KQL Queries: {query_count} executed
                    - Findings: {'; '.join(findings_summary)}
                    - IP Threat Score: {ip_threat_score}/100
                    
                    Classification Rules:
                    TRUE_POSITIVE if: IP threat score >50, unusual patterns in KQL data, high-risk factors
                    FALSE_POSITIVE if: Low risk score <5, normal patterns, clean IP reputation
                    
                    REQUIRED OUTPUT FORMAT:
                    VERDICT: [TRUE_POSITIVE or FALSE_POSITIVE]
                    
                    EVIDENCE:
                    [Detailed explanation of why this classification was chosen based on the investigation data]
                    
                    You MUST start your response with exactly 'VERDICT: TRUE_POSITIVE' or 'VERDICT: FALSE_POSITIVE'""",
                    agent=self.agents['security_analyst'],
                    expected_output="Classification verdict starting with 'VERDICT: TRUE_POSITIVE' or 'VERDICT: FALSE_POSITIVE' followed by evidence"
                )
                
                # Execute simplified crew
                crew = Crew(
                    agents=[self.agents['security_analyst']],
                    tasks=[classification_task],
                    process=Process.sequential,
                    verbose=False
                )
                
                result = crew.kickoff()
                
                # Add query count and SQL queries to results for dashboard
                kql_results['query_count'] = query_count
                
                # Add SQL queries to results for display
                queries = self.generate_dynamic_kql_queries(alert_data)
                for i, query in enumerate(queries):
                    kql_results[f'query_{i+1}_sql'] = query
                
                return str(result), kql_results
                
            except Exception as e:
                error_msg = str(e)
                if "rate_limit" in error_msg.lower() or "ratelimit" in error_msg.lower():
                    print(f"   ⚠️  Rate limit hit on attempt {attempt + 1}, rotating API key...")
                    if attempt < self.max_retries - 1:
                        self.key_manager.rotate_key()
                        import time
                        time.sleep(10)  # Longer pause to let rate limits reset
                        continue
                    else:
                        print(f"   ❌ All API keys exhausted, using fallback classification")
                        raise e
                else:
                    # Non-rate-limit error, don't retry
                    raise e
        
        # This should not be reached, but just in case
        raise Exception("All retry attempts failed")


def main():
    """Process alerts from JSON file with IP checks, KQL investigations, and true/false positive decisions"""
    analyzer = CrewAIAnalyzer()
    
    # Load alerts from the specific JSON file
    json_file = "sentinel_logs1/sentinel_logs_2025-11-12 04-00-04-30/correlation_analysis_sentinel_user_data_20251112_0400_0430.json"
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {json_file}")
        return
    
    # Extract all alerts from all priority levels
    all_alerts = (
        data.get('high_priority_events', []) + 
        data.get('medium_priority_events', []) + 
        data.get('low_priority_events', [])
    )
    
    print(f"\n🔍 Processing {len(all_alerts)} alerts from {json_file}")
    print("=" * 80)
    
    results = []
    
    for i, alert in enumerate(all_alerts):
        user = alert.get('user_principal_name', 'Unknown')
        risk_score = alert.get('risk_score', 0)
        
        print(f"\n📋 Alert {i+1}/{len(all_alerts)}: {user} (Risk Score: {risk_score})")
        print(f"   Risk Factors: {alert.get('risk_factors', [])}")
        
        try:
            # Perform comprehensive analysis with IP checks and KQL
            print("   🔎 Running IP reputation checks and KQL investigations...")
            analysis, investigation_data = analyzer.analyze_alert_with_crew(alert)
            
            # Extract verdict from analysis with improved parsing
            analysis_upper = analysis.upper()
            
            # Look for explicit verdict statements first
            if "VERDICT: FALSE_POSITIVE" in analysis_upper:
                verdict = "FALSE_POSITIVE"
                status_icon = "✅"
            elif "VERDICT: TRUE_POSITIVE" in analysis_upper:
                verdict = "TRUE_POSITIVE"
                status_icon = "🚨"
            # Fallback to general pattern matching
            elif "FALSE_POSITIVE" in analysis_upper and "TRUE_POSITIVE" not in analysis_upper:
                verdict = "FALSE_POSITIVE"
                status_icon = "✅"
            elif "TRUE_POSITIVE" in analysis_upper and "FALSE_POSITIVE" not in analysis_upper:
                verdict = "TRUE_POSITIVE"
                status_icon = "🚨"
            else:
                # If no clear verdict found, use risk score as fallback
                verdict = "TRUE_POSITIVE" if risk_score >= 7 else "FALSE_POSITIVE"
                status_icon = "🚨" if verdict == "TRUE_POSITIVE" else "✅"
                print(f"   ⚠️  No clear verdict found in analysis, using fallback: {verdict}")
            
            print(f"   {status_icon} VERDICT: {verdict}")
            # Only show debug info if verdict extraction failed
            if "⚠️" in str(status_icon) or ("VERDICT:" not in analysis.upper()):
                print(f"   📝 RAW ANALYSIS: {analysis[:200]}...")
                print(f"   🔍 VERDICT EXTRACTION: Looking for 'VERDICT: TRUE_POSITIVE' or 'VERDICT: FALSE_POSITIVE'")
            
            # Get query count from investigation data
            query_count = investigation_data.get('query_count', 0)
            
            # Store comprehensive results
            results.append({
                'alert_id': i+1,
                'user_principal_name': user,
                'risk_score': risk_score,
                'risk_factors': alert.get('risk_factors', []),
                'verdict': verdict,
                'analysis': analysis,
                'investigation_data': investigation_data,
                'query_count': query_count,
                'ip_addresses': [loc.get('ip_address') for loc in alert.get('locations', [])],
                'applications': [app.get('app_name') for app in alert.get('applications', [])],
                'timestamp': datetime.now().isoformat()
            })
            
            print(f"   📈 KQL Queries Executed: {query_count}")
            
        except Exception as e:
            # Fallback classification based on risk score
            fallback_verdict = "TRUE_POSITIVE" if risk_score >= 7 else "FALSE_POSITIVE"
            status_icon = "🚨" if fallback_verdict == "TRUE_POSITIVE" else "✅"
            
            print(f"   ⚠️  Analysis error - using fallback classification")
            print(f"   {status_icon} VERDICT: {fallback_verdict} (based on risk score)")
            
            # Get basic investigation data for fallback
            try:
                fallback_investigation = analyzer.investigate_with_kql(alert)
                query_count = len([k for k in fallback_investigation.keys() if k.startswith('query_') and not k.endswith('_sql')])
                fallback_investigation['query_count'] = query_count
            except:
                fallback_investigation = {'query_count': 0}
            
            results.append({
                'alert_id': i+1,
                'user_principal_name': user,
                'risk_score': risk_score,
                'risk_factors': alert.get('risk_factors', []),
                'verdict': fallback_verdict,
                'analysis': f"Analysis failed - classified based on risk score ({risk_score}): {str(e)}",
                'investigation_data': fallback_investigation,
                'query_count': fallback_investigation.get('query_count', 0),
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
    # Save results
    output_file = 'alert_analysis_results.json'
    with open(output_file, 'w') as f:
        json.dump({
            'source_file': json_file,
            'total_alerts': len(all_alerts),
            'true_positives': len([r for r in results if r['verdict'] == 'TRUE_POSITIVE']),
            'false_positives': len([r for r in results if r['verdict'] == 'FALSE_POSITIVE']),
            'analysis_timestamp': datetime.now().isoformat(),
            'results': results
        }, f, indent=2)
    
    # Summary
    tp_count = len([r for r in results if r['verdict'] == 'TRUE_POSITIVE'])
    fp_count = len([r for r in results if r['verdict'] == 'FALSE_POSITIVE'])
    
    print("\n" + "=" * 80)
    print(f"✅ Analysis Complete: {len(results)} alerts processed")
    print(f"🚨 True Positives: {tp_count}")
    print(f"✅ False Positives: {fp_count}")
    print(f"📄 Results saved to: {output_file}")

# Backward compatibility
class SimpleAnalyzer(CrewAIAnalyzer):
    def analyze_alert_simple(self, alert_data):
        """Simple wrapper that ensures query count and SQL queries are properly returned"""
        analysis, investigation_data = self.analyze_alert_with_crew(alert_data)
        
        # Ensure query_count is in investigation_data
        if 'query_count' not in investigation_data:
            query_count = len([k for k in investigation_data.keys() if k.startswith('query_') and not k.endswith('_sql')])
            investigation_data['query_count'] = query_count
        
        # Ensure SQL queries are included for display
        if not any(k.endswith('_sql') for k in investigation_data.keys()):
            queries = self.generate_dynamic_kql_queries(alert_data)
            for i, query in enumerate(queries):
                investigation_data[f'query_{i+1}_sql'] = query
            
        return analysis, investigation_data

if __name__ == "__main__":
    main()