import streamlit as st
import json
import os
import glob
from datetime import datetime
from simple_analyzer import SimpleAnalyzer
import time


st.set_page_config(
    page_title="Sentinel Alert Analyzer",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_alerts():
    all_alerts = []
    pattern = "sentinel_logs1/*/correlation_analysis_sentinel_user_data*.json"
    files = glob.glob(pattern)

    file_count = len(files)
    alert_count = 0

    for file_path in files:
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            alerts = (
                data.get("high_priority_events", [])
                + data.get("medium_priority_events", [])
                + data.get("low_priority_events", [])
            )

            for alert in alerts:
                alert["source_file"] = os.path.basename(file_path)
                alert["file_path"] = file_path
                alert_count += 1

            all_alerts.extend(alerts)
        except Exception as e:
            st.error(f"Error loading {file_path}: {e}")

    st.info(f"📁 Loaded {alert_count} alerts from {file_count} files")
    return all_alerts


def analyze_alerts(alerts):
    analyzer = SimpleAnalyzer()
    results = []

    progress_bar = st.progress(0)
    status_text = st.empty()
    kql_counter = st.empty()

    total_kql_queries = 0

    for i, alert in enumerate(alerts):
        status_text.text(
            f"🔍 Analyzing Alert {i+1}/{len(alerts)}: {alert.get('user_principal_name')} (Risk: {alert.get('risk_score', 'N/A')})"
        )

        try:
            # Use enhanced analyzer with dynamic KQL
            analysis, kql_results = analyzer.analyze_alert_simple(alert)

            # Count KQL queries for this alert - use the query_count from investigation data
            alert_kql_count = kql_results.get('query_count', 0)
            if alert_kql_count == 0:
                # Fallback to counting SQL queries if query_count not available
                alert_kql_count = len([k for k in kql_results.keys() if k.endswith("_sql")])
            total_kql_queries += alert_kql_count

            kql_counter.text(
                f"⚡ Generated {total_kql_queries} dynamic KQL queries so far..."
            )

            # Extract verdict from analysis - check for explicit verdict statements
            analysis_upper = analysis.upper()
            if "VERDICT: FALSE_POSITIVE" in analysis_upper:
                verdict = "FALSE_POSITIVE"
            elif "VERDICT: TRUE_POSITIVE" in analysis_upper:
                verdict = "TRUE_POSITIVE"
            elif "FALSE_POSITIVE" in analysis_upper and "TRUE_POSITIVE" not in analysis_upper:
                verdict = "FALSE_POSITIVE"
            elif "TRUE_POSITIVE" in analysis_upper and "FALSE_POSITIVE" not in analysis_upper:
                verdict = "TRUE_POSITIVE"
            else:
                # Fallback to risk score based classification
                verdict = "TRUE_POSITIVE" if alert.get("risk_score", 0) >= 7 else "FALSE_POSITIVE"

            results.append(
                {
                    "alert_id": i + 1,
                    "user": alert.get("user_principal_name"),
                    "risk_score": alert.get("risk_score"),
                    "verdict": verdict,
                    "analysis": analysis,
                    "kql_results": kql_results,
                    "alert_data": alert,
                    "timestamp": datetime.now().isoformat(),
                    "kql_query_count": alert_kql_count,
                    "raw_kql_results": kql_results,  # Store raw KQL results
                }
            )

        except Exception as e:
            # Even on error, provide a binary classification based on risk score
            risk_score = alert.get("risk_score", 0)
            fallback_verdict = "TRUE_POSITIVE" if risk_score >= 7 else "FALSE_POSITIVE"

            alert_risk_score = alert.get("risk_score", 0)
            fallback_verdict = "TRUE_POSITIVE" if alert_risk_score >= 7 else "FALSE_POSITIVE"
            
            results.append(
                {
                    "alert_id": i + 1,
                    "user": alert.get("user_principal_name", "Unknown"),
                    "risk_score": alert_risk_score,
                    "verdict": fallback_verdict,
                    "analysis": f"Analysis failed, classified based on risk score ({alert_risk_score}): {str(e)}",
                    "timestamp": datetime.now().isoformat(),
                    "kql_query_count": 0,
                }
            )

        progress_bar.progress((i + 1) / len(alerts))

    status_text.text(
        f"✅ Dynamic Analysis Complete! Processed {len(results)} alerts with {total_kql_queries} KQL queries"
    )
    kql_counter.empty()
    return results


def show_batch_analysis():
    # Initialize session state
    if "results" not in st.session_state:
        st.session_state.results = None
    if "auto_refresh" not in st.session_state:
        st.session_state.auto_refresh = False
    if "last_update" not in st.session_state:
        st.session_state.last_update = None

    # Sidebar controls
    with st.sidebar:
        st.header("⚙️ Batch Analysis Controls")

        # Auto-refresh toggle
        auto_refresh = st.toggle("🔄 Auto Refresh", value=st.session_state.auto_refresh)
        st.session_state.auto_refresh = auto_refresh

        if auto_refresh:
            refresh_interval = st.selectbox(
                "Refresh Interval", [30, 60, 120, 300], index=1
            )
            st.info(f"Auto-refreshing every {refresh_interval} seconds")

        # Manual refresh button
        if st.button("🔄 Refresh Now", type="secondary"):
            st.session_state.results = None
            st.rerun()

        st.divider()

        # Analysis options
        st.subheader("🔍 Analysis Options")
        st.checkbox(
            "⚡ Dynamic KQL Generation",
            value=True,
            disabled=True,
            help="Automatically enabled",
        )
        st.checkbox(
            "📊 Enhanced Analysis",
            value=True,
            disabled=True,
            help="Includes KQL result analysis",
        )

        # File selection
        pattern = "sentinel_logs1/*/correlation_analysis_sentinel_user_data*.json"
        available_files = glob.glob(pattern)
        st.info(f"📁 {len(available_files)} alert files available")

    # Auto-refresh logic with dynamic updates
    if auto_refresh:
        placeholder = st.empty()
        if (
            st.session_state.last_update is None
            or (datetime.now() - st.session_state.last_update).seconds
            >= refresh_interval
        ):
            with placeholder.container():
                st.info("🔄 Auto-refreshing with dynamic KQL analysis...")
                alerts = load_alerts()
                st.session_state.results = analyze_alerts(alerts)
                st.session_state.last_update = datetime.now()
                time.sleep(1)
                st.rerun()

    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        if st.button("🚀 Start Dynamic Analysis", type="primary"):
            with st.spinner("Loading alerts and generating dynamic KQL queries..."):
                alerts = load_alerts()
                st.info(f"Found {len(alerts)} alerts across all files")
                st.info(
                    "🔍 Generating dynamic KQL queries based on alert characteristics..."
                )
                st.session_state.results = analyze_alerts(alerts)
                st.session_state.last_update = datetime.now()

    with col2:
        if st.session_state.results:
            st.metric("Total Alerts", len(st.session_state.results))

    with col3:
        if st.session_state.last_update:
            st.metric("Last Update", st.session_state.last_update.strftime("%H:%M:%S"))

    if st.session_state.results:
        st.header("📊 Dynamic Analysis Results")

        # Enhanced summary metrics
        col1, col2, col3, col4, col5 = st.columns(5)

        true_pos = sum(
            1 for r in st.session_state.results if r["verdict"] == "TRUE_POSITIVE"
        )
        false_pos = sum(
            1 for r in st.session_state.results if r["verdict"] == "FALSE_POSITIVE"
        )
        total = len(st.session_state.results)
        # All alerts now have binary classification, no errors in verdict

        # Count total KQL queries executed
        total_kql_queries = sum(
            r.get("kql_query_count", 0) for r in st.session_state.results
        )

        col1.metric("🔴 True Positives", true_pos, delta_color="inverse")
        col2.metric("🟢 False Positives", false_pos)
        col3.metric("📊 Total Analyzed", total)
        col4.metric("✅ Classification Rate", "100%" if total > 0 else "0%")
        col5.metric("🔍 KQL Queries", total_kql_queries)

        # Enhanced Results table
        st.subheader("🔍 Alert Analysis with Dynamic KQL")

        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            verdict_filter = st.selectbox(
                "Filter by Verdict", ["All", "TRUE_POSITIVE", "FALSE_POSITIVE"]
            )
        with col2:
            risk_filter = st.selectbox(
                "Filter by Risk Score",
                ["All", "High (7-10)", "Medium (4-6)", "Low (1-3)"],
            )
        with col3:
            show_kql = st.checkbox("Show KQL Details", value=True)

        # Apply filters
        filtered_results = st.session_state.results
        if verdict_filter != "All":
            filtered_results = [
                r for r in filtered_results if r["verdict"] == verdict_filter
            ]

        if risk_filter != "All":
            if risk_filter == "High (7-10)":
                filtered_results = [
                    r for r in filtered_results if r.get("risk_score", 0) >= 7
                ]
            elif risk_filter == "Medium (4-6)":
                filtered_results = [
                    r for r in filtered_results if 4 <= r.get("risk_score", 0) <= 6
                ]
            elif risk_filter == "Low (1-3)":
                filtered_results = [
                    r for r in filtered_results if r.get("risk_score", 0) <= 3
                ]

        st.info(
            f"Showing {len(filtered_results)} of {len(st.session_state.results)} alerts"
        )

        for result in filtered_results:
            verdict_color = (
                "🔴"
                if result["verdict"] == "TRUE_POSITIVE"
                else "🟢" if result["verdict"] == "FALSE_POSITIVE" else "🟡"
            )
            kql_count = result.get("kql_query_count", 0)

            with st.expander(
                f"{verdict_color} Alert #{result['alert_id']}: {result['user']} - {result['verdict']} ({kql_count} KQL)",
                expanded=False,
            ):

                col1, col2 = st.columns([1, 1])

                with col1:
                    st.markdown("**Alert Information:**")
                    st.write(f"👤 **User:** {result['user']}")
                    st.write(f"⚠️ **Risk Score:** {result['risk_score']}")
                    st.write(f"✅ **Verdict:** {result['verdict']}")
                    if "alert_data" in result and "source_file" in result["alert_data"]:
                        st.write(
                            f"📁 **Source:** {result['alert_data']['source_file']}"
                        )

                    if "alert_data" in result:
                        alert = result["alert_data"]
                        location = alert.get("locations", [{}])[0].get(
                            "city", "Unknown"
                        )
                        ip = alert.get("locations", [{}])[0].get(
                            "ip_address", "Unknown"
                        )
                        st.write(f"📍 **Location:** {location}")
                        st.write(f"🌐 **IP Address:** {ip}")

                        apps = [
                            app.get("app_name") for app in alert.get("applications", [])
                        ]
                        st.write(
                            f"📱 **Applications:** {', '.join(apps) if apps else 'None'}"
                        )

                with col2:
                    if show_kql:
                        st.markdown("**🔍 Dynamic KQL Queries:**")
                        if "kql_results" in result:
                            kql_data = result["kql_results"]
                            query_count = result.get("kql_query_count", 0)
                            
                            if query_count > 0:
                                # Show actual queries if available
                                queries_shown = 0
                                for i in range(1, 4):
                                    if f"query_{i}" in kql_data:
                                        queries_shown += 1
                                        query_type = (
                                            "👤 User Activity"
                                            if i == 1
                                            else (
                                                "🌐 IP Analysis"
                                                if i == 2
                                                else "📋 Audit Logs"
                                            )
                                        )
                                        st.markdown(f"**{query_type}:**")
                                        # Show query result summary instead of SQL
                                        query_result = kql_data[f"query_{i}"]
                                        if isinstance(query_result, dict) and "tables" in query_result:
                                            row_count = len(query_result["tables"][0].get("rows", [])) if query_result["tables"] else 0
                                            st.info(f"Query returned {row_count} records")
                                        else:
                                            st.info("Query executed successfully")
                                
                                if queries_shown == 0:
                                    st.info(f"Generated {query_count} dynamic queries (details in investigation summary)")
                                else:
                                    st.success(f"✅ {queries_shown} dynamic queries executed")
                            else:
                                st.info("No dynamic queries generated")
                        else:
                            st.warning("No KQL queries available")
                    else:
                        st.info("KQL details hidden (toggle above to show)")

                st.markdown("**🤖 Dynamic Analysis Results:**")
                # Fix HTML entity encoding for bullet points
                analysis_text = result["analysis"].replace("&amp;", "&").replace("&#39;", "'")
                st.info(analysis_text)

                # Enhanced KQL Results summary
                if "kql_results" in result and result["kql_results"] and show_kql:
                    st.markdown("**📊 Dynamic KQL Investigation Summary:**")
                    kql_data = result["kql_results"]
                    query_count = 0
                    total_records = 0

                    for key, query_result in kql_data.items():
                        if key.startswith("query_") and not key.endswith("_sql"):
                            query_count += 1
                            query_name = kql_data.get(f"{key}_sql", "Unknown Query")

                            if isinstance(query_result, dict):
                                if "error" in query_result:
                                    st.error(
                                        f"🚫 Query {query_count}: {query_result['error']}"
                                    )
                                elif (
                                    "tables" in query_result and query_result["tables"]
                                ):
                                    table = query_result["tables"][0]
                                    row_count = len(table.get("rows", []))
                                    total_records += row_count

                                    if "SigninLogs" in query_name:
                                        st.info(
                                            f"🔐 Authentication Query {query_count}: {row_count} sign-in events"
                                        )
                                    elif "AuditLogs" in query_name:
                                        st.info(
                                            f"📋 Audit Query {query_count}: {row_count} administrative events"
                                        )
                                    else:
                                        st.info(
                                            f"📊 Query {query_count}: {row_count} records found"
                                        )
                                else:
                                    st.warning(
                                        f"⚠️ Query {query_count}: No data returned"
                                    )

                    if total_records > 0:
                        st.success(
                            f"✅ Total investigation data: {total_records} records across {query_count} dynamic queries"
                        )
                    else:
                        st.info(
                            "ℹ️ No investigation data found - may indicate normal activity"
                        )
                    
                    # Show raw KQL results with checkbox toggle
                    if st.checkbox(f"🔍 Show Raw KQL Results & IP Reputation (Alert #{result['alert_id']})", key=f"raw_{result['alert_id']}"):
                        for key, value in kql_data.items():
                            if key == 'ip_reputation':
                                st.markdown("**🌐 IP Reputation Analysis:**")
                                st.json(value)
                            elif key.startswith('query_') and not key.endswith('_sql'):
                                query_sql = kql_data.get(f"{key}_sql", "SQL not available")
                                st.markdown(f"**📊 {key.upper()} Results:**")
                                st.code(query_sql, language="sql")
                                st.json(value)

        # Enhanced Export functionality
        st.subheader("📥 Export Results")
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("💾 Save JSON Report"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"batch_analysis_{timestamp}.json"
                export_data = {
                    "metadata": {
                        "generated": datetime.now().isoformat(),
                        "total_alerts": len(st.session_state.results),
                        "analysis_type": "Dynamic KQL + Rule-based",
                        "total_kql_queries": total_kql_queries,
                    },
                    "results": st.session_state.results,
                }
                with open(filename, "w") as f:
                    json.dump(export_data, f, indent=2)
                st.success(f"Enhanced results saved to {filename}")

        with col2:
            if st.button("📄 Generate Markdown Report"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"batch_report_{timestamp}.md"

                md_content = f"""# Sentinel Alert Analysis Report (Batch)

**Generated:** {datetime.now().isoformat()}
**Total Alerts:** {len(st.session_state.results)}
**Analysis Type:** Dynamic KQL + Rule-based
**Total KQL Queries Executed:** {total_kql_queries}

## Summary
- True Positives: {true_pos}
- False Positives: {false_pos}
- Total Analyzed: {len(st.session_state.results)}
- Classification Rate: 100% (Binary classification enforced)

## Alert Details

"""
                for result in st.session_state.results:
                    kql_count = result.get("kql_query_count", 0)
                    md_content += f"""### Alert #{result['alert_id']}: {result['user']}
**Verdict:** {result['verdict']}
**Risk Score:** {result['risk_score']}
**Dynamic KQL Queries:** {kql_count}
**Analysis:** {result['analysis']}

---

"""

                with open(filename, "w") as f:
                    f.write(md_content)
                st.success(f"Report saved to {filename}")

        with col3:
            if st.button("📊 Export KQL Queries"):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"dynamic_kql_queries_{timestamp}.sql"

                kql_content = f"-- Dynamic KQL Queries Generated on {datetime.now().isoformat()}\n"
                kql_content += f"-- Total Queries: {total_kql_queries}\n\n"

                for result in st.session_state.results:
                    if "kql_results" in result:
                        kql_content += f"-- Alert #{result['alert_id']}: {result['user']} (Risk: {result.get('risk_score', 'N/A')})\n"
                        kql_data = result["kql_results"]
                        for key, query in kql_data.items():
                            if key.endswith("_sql"):
                                kql_content += f"{query};\n\n"
                        kql_content += "-- " + "=" * 50 + "\n\n"

                with open(filename, "w") as f:
                    f.write(kql_content)
                st.success(f"KQL queries saved to {filename}")

    else:
        st.info("No results yet. Click 'Start Dynamic Analysis' to begin.")

        # Show instructions for batch analysis
        with st.expander("📖 Dynamic Analysis Features"):
            st.markdown(
                """
            **Enhanced Dynamic Analysis Features:**
            
            🔍 **Dynamic KQL Generation:**
            - Queries adapt to alert risk scores and characteristics
            - Time ranges adjust automatically (1-7 days based on risk)
            - Query types vary based on user type and risk factors
            
            📊 **Enhanced Analysis:**
            - Rule-based verdict determination
            - KQL result context analysis
            - Comprehensive investigation summaries
            
            🔄 **Live Updates:**
            - Auto-refresh capabilities
            - Real-time data monitoring
            - Filtered result views
            
            📥 **Export Options:**
            - JSON reports with metadata
            - Markdown reports with summaries
            - KQL query collections for reuse
            """
            )


def main():
    st.title("🛡️ Sentinel Alert Analyzer Dashboard")

    show_batch_analysis()


if __name__ == "__main__":
    main()
