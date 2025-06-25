import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import re
from datetime import datetime, timedelta
import os
from typing import Dict, List, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EduroamLogParser:
    """Parser for eduroam authentication and F-TICKS logs"""
    
    def __init__(self, log_file_path: str = "logs.txt"):
        self.log_file_path = log_file_path
        # Updated pattern for your log format
        self.auth_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}):\s+'
            r'(?P<result>Access-Accept|Access-Reject)\s+'
            r'for\s+user\s+(?P<username>[^\s]+)\s+'
            r'stationid\s+(?P<stationid>[^\s]+)\s*'
            r'(?:cui\s+(?P<cui>[^\s]+)\s+)?'
            r'from\s+(?P<from_server>[^\s]+)\s+'
            r'(?:\((?P<reason>[^)]+)\)\s+)?'
            r'to\s+(?P<to_server>[^\s]+)\s+'
            r'(?:\((?P<ip_address>[\d.]+)\))?'
            r'(?:\s+operator\s+(?P<operator>\S+))?'
        )
        
        self.fticks_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}):\s+'
            r'F-TICKS/(?P<federation>[^/]+)/(?P<version>[^#]+)#'
            r'REALM=(?P<realm>[^#]*)#'
            r'VISCOUNTRY=(?P<viscountry>[^#]+)#'
            r'VISINST=(?P<visinst>[^#]+)#'
            r'(?:CSI=(?P<csi>[^#]+)#)?'
            r'RESULT=(?P<result>[^#]+)#'
        )
        
        # Pattern for other log entries (like radudpget)
        self.other_pattern = re.compile(
            r'(?P<timestamp>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}):\s+'
            r'(?P<message>.*)'
        )
    
    def parse_logs(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Parse logs and return authentication, F-TICKS, and other log dataframes"""
        if not os.path.exists(self.log_file_path):
            logger.warning(f"Log file {self.log_file_path} not found")
            return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
        
        auth_data = []
        fticks_data = []
        other_data = []
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to match authentication logs first
                    auth_match = self.auth_pattern.search(line)
                    if auth_match:
                        auth_data.append(self._parse_auth_entry(auth_match, line))
                        continue
                    
                    # Try to match F-TICKS logs
                    fticks_match = self.fticks_pattern.search(line)
                    if fticks_match:
                        fticks_data.append(self._parse_fticks_entry(fticks_match, line))
                        continue
                    
                    # Capture other log entries
                    other_match = self.other_pattern.search(line)
                    if other_match:
                        other_data.append(self._parse_other_entry(other_match, line))
        
        except Exception as e:
            logger.error(f"Error parsing logs: {e}")
            st.error(f"Error parsing log file: {e}")
            return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
        
        # Convert to DataFrames
        auth_df = pd.DataFrame(auth_data) if auth_data else pd.DataFrame()
        fticks_df = pd.DataFrame(fticks_data) if fticks_data else pd.DataFrame()
        other_df = pd.DataFrame(other_data) if other_data else pd.DataFrame()
        
        # Process authentication DataFrame
        if not auth_df.empty:
            auth_df['timestamp'] = pd.to_datetime(auth_df['timestamp'], format='%a %b %d %H:%M:%S %Y', errors='coerce')
            auth_df['date'] = auth_df['timestamp'].dt.date
            auth_df['hour'] = auth_df['timestamp'].dt.hour
            auth_df['day_of_week'] = auth_df['timestamp'].dt.day_name()
            
            # Extract domain from username
            auth_df['user_domain'] = auth_df['username'].str.extract(r'@([^@]+)$')
            auth_df['user_domain'] = auth_df['user_domain'].fillna('no-domain')
            
            # Clean server names
            auth_df['from_server'] = auth_df['from_server'].fillna('unknown')
            auth_df['to_server'] = auth_df['to_server'].fillna('unknown')
        
        # Process F-TICKS DataFrame
        if not fticks_df.empty:
            fticks_df['timestamp'] = pd.to_datetime(fticks_df['timestamp'], format='%a %b %d %H:%M:%S %Y', errors='coerce')
            fticks_df['date'] = fticks_df['timestamp'].dt.date
            fticks_df['hour'] = fticks_df['timestamp'].dt.hour
            fticks_df['day_of_week'] = fticks_df['timestamp'].dt.day_name()
        
        # Process other logs DataFrame
        if not other_df.empty:
            other_df['timestamp'] = pd.to_datetime(other_df['timestamp'], format='%a %b %d %H:%M:%S %Y', errors='coerce')
            other_df['date'] = other_df['timestamp'].dt.date
        
        return auth_df, fticks_df, other_df
    
    def _parse_auth_entry(self, match: re.Match, full_line: str) -> Dict:
        """Parse authentication log entry"""
        data = match.groupdict()
        
        return {
            'timestamp': data['timestamp'],
            'result': data['result'],
            'username': data['username'],
            'stationid': data['stationid'],
            'cui': data.get('cui'),
            'from_server': data['from_server'],
            'to_server': data['to_server'],
            'ip_address': data.get('ip_address'),
            'reason': data.get('reason'),
            'operator': data.get('operator'),
            'full_line': full_line
        }
    
    def _parse_fticks_entry(self, match: re.Match, full_line: str) -> Dict:
        """Parse F-TICKS log entry"""
        data = match.groupdict()
        
        return {
            'timestamp': data['timestamp'],
            'federation': data['federation'],
            'version': data['version'],
            'realm': data['realm'],
            'viscountry': data['viscountry'],
            'visinst': data['visinst'],
            'csi': data.get('csi'),
            'result': data['result'],
            'full_line': full_line
        }
    
    def _parse_other_entry(self, match: re.Match, full_line: str) -> Dict:
        """Parse other log entries"""
        data = match.groupdict()
        
        return {
            'timestamp': data['timestamp'],
            'message': data['message'],
            'full_line': full_line
        }

class DashboardComponents:
    """Reusable dashboard components"""
    
    @staticmethod
    def create_metric_cards(df: pd.DataFrame, result_col: str = 'result'):
        """Create metric cards for overview"""
        if df.empty:
            st.warning("No data available")
            return
        
        total_attempts = len(df)
        if result_col == 'result' and 'Access-Accept' in df[result_col].values:
            successful = len(df[df[result_col] == 'Access-Accept'])
            failed = len(df[df[result_col] == 'Access-Reject'])
            success_rate = (successful / total_attempts * 100) if total_attempts > 0 else 0
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Attempts", f"{total_attempts:,}")
            with col2:
                st.metric("Successful", f"{successful:,}", delta=f"{success_rate:.1f}%")
            with col3:
                st.metric("Failed", f"{failed:,}")
            with col4:
                unique_users = df['username'].nunique() if 'username' in df.columns else 0
                st.metric("Unique Users", f"{unique_users:,}")
        else:
            # For F-TICKS or other data
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Records", f"{total_attempts:,}")
            with col2:
                if 'realm' in df.columns:
                    unique_realms = df['realm'].nunique()
                    st.metric("Unique Realms", f"{unique_realms:,}")

def create_auth_dashboard(auth_df: pd.DataFrame):
    """Create authentication dashboard tab"""

    st.subheader("📋 Recent Authentication Attempts")
    display_cols = ['timestamp', 'result', 'username', 'from_server', 'to_server', 'ip_address', 'reason', 'operator']
    available_cols = [col for col in display_cols if col in auth_df.columns]
    
    if available_cols:
        st.dataframe(
            auth_df[available_cols].sort_values('timestamp', ascending=True),
            use_container_width=True
        )




    st.header("🔐 Authentication Analysis")
    
    if auth_df.empty:
        st.warning("No authentication data found in the logs.")
        st.info("Expected format: Lines containing 'Access-Accept' or 'Access-Reject' with 'for user' pattern")
        return
    
    # Metrics overview
    DashboardComponents.create_metric_cards(auth_df)
    
    # Debug section
    with st.expander("🔍 Debug: Parsing Information", expanded=False):
        st.write(f"**Total records parsed:** {len(auth_df)}")
        if not auth_df.empty:
            st.write("**Sample parsed data:**")
            debug_cols = ['timestamp', 'result', 'username', 'from_server', 'to_server', 'ip_address', 'reason']
            available_debug_cols = [col for col in debug_cols if col in auth_df.columns]
            st.dataframe(auth_df[available_debug_cols].head(5))
            
            # Show statistics
            st.write(f"**Records with usernames:** {auth_df['username'].notna().sum()} / {len(auth_df)}")
            st.write(f"**Records with IP addresses:** {auth_df['ip_address'].notna().sum()} / {len(auth_df)}")
            st.write(f"**Records with reasons:** {auth_df['reason'].notna().sum()} / {len(auth_df)}")
    
    # Sidebar filters
    st.sidebar.header("🔍 Authentication Filters")
    
    # Date range filter - Fixed the indentation and logic
    if 'date' in auth_df.columns and not auth_df['date'].isna().all():
        min_date = auth_df['date'].min()
        max_date = auth_df['date'].max()

        date_range = st.sidebar.date_input(
            "Date Range",
            value=(min_date, max_date),
            min_value=min_date,
            max_value=max_date
        )

        if isinstance(date_range, tuple) and len(date_range) == 2:
            # Convert to pandas datetime for proper filtering
            start_date = pd.to_datetime(date_range[0]).date()
            end_date = pd.to_datetime(date_range[1]).date()

            auth_df = auth_df[
                (auth_df['date'] >= start_date) &
                (auth_df['date'] <= end_date)
            ]
    
    # User domain filter
    if 'user_domain' in auth_df.columns:
        domains = ['All'] + sorted(auth_df['user_domain'].unique().tolist())
        selected_domain = st.sidebar.selectbox("User Domain", domains)
        if selected_domain != 'All':
            auth_df = auth_df[auth_df['user_domain'] == selected_domain]
    
    # Server filter
    if 'from_server' in auth_df.columns:
        servers = ['All'] + sorted(auth_df['from_server'].unique().tolist())
        selected_server = st.sidebar.selectbox("From Server", servers)
        if selected_server != 'All':
            auth_df = auth_df[auth_df['from_server'] == selected_server]
    
    # Result filter
    if 'result' in auth_df.columns:
        results = ['All'] + sorted(auth_df['result'].unique().tolist())
        selected_result = st.sidebar.selectbox("Result", results)
        if selected_result != 'All':
            auth_df = auth_df[auth_df['result'] == selected_result]
    
    if auth_df.empty:
        st.warning("No data matches the selected filters.")
        return
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Success/Failure pie chart
        if 'result' in auth_df.columns:
            result_counts = auth_df['result'].value_counts()
            fig_pie = px.pie(
                values=result_counts.values,
                names=result_counts.index,
                title="Authentication Results Distribution",
                color_discrete_map={
                    'Access-Accept': '#2E8B57',
                    'Access-Reject': '#DC143C'
                }
            )
            fig_pie.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Top user domains
        if 'user_domain' in auth_df.columns:
            domain_counts = auth_df['user_domain'].value_counts().head(10)
            fig_domain = px.bar(
                x=domain_counts.values,
                y=domain_counts.index,
                orientation='h',
                title="Top 10 User Domains by Authentication Attempts",
                labels={'x': 'Attempts', 'y': 'Domain'}
            )
            fig_domain.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_domain, use_container_width=True)
    
    # Server analysis
    col1, col2 = st.columns(2)
    
    with col1:
        # From servers
        if 'from_server' in auth_df.columns:
            from_server_counts = auth_df['from_server'].value_counts().head(10)
            fig_from = px.bar(
                x=from_server_counts.values,
                y=from_server_counts.index,
                orientation='h',
                title="Top 10 Source Servers",
                labels={'x': 'Count', 'y': 'Server'}
            )
            fig_from.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_from, use_container_width=True)
    
    with col2:
        # To servers
        if 'to_server' in auth_df.columns:
            to_server_counts = auth_df['to_server'].value_counts().head(10)
            fig_to = px.bar(
                x=to_server_counts.values,
                y=to_server_counts.index,
                orientation='h',
                title="Top 10 Destination Servers",
                labels={'x': 'Count', 'y': 'Server'}
            )
            fig_to.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_to, use_container_width=True)
    
    # Time series analysis
    if 'timestamp' in auth_df.columns and not auth_df['timestamp'].isna().all():
        st.subheader("📈 Time Series Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Hourly distribution
            if 'hour' in auth_df.columns:
                hourly_data = auth_df.groupby(['hour', 'result']).size().reset_index(name='count')
                fig_hourly = px.bar(
                    hourly_data,
                    x='hour',
                    y='count',
                    color='result',
                    title="Hourly Authentication Distribution",
                    labels={'hour': 'Hour of Day', 'count': 'Count'},
                    color_discrete_map={
                        'Access-Accept': '#2E8B57',
                        'Access-Reject': '#DC143C'
                    }
                )
                st.plotly_chart(fig_hourly, use_container_width=True)
        
        with col2:
            # Day of week distribution
            if 'day_of_week' in auth_df.columns:
                dow_data = auth_df.groupby(['day_of_week', 'result']).size().reset_index(name='count')
                # Reorder days
                day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                dow_data['day_of_week'] = pd.Categorical(dow_data['day_of_week'], categories=day_order, ordered=True)
                dow_data = dow_data.sort_values('day_of_week')
                
                fig_dow = px.bar(
                    dow_data,
                    x='day_of_week',
                    y='count',
                    color='result',
                    title="Day of Week Authentication Distribution",
                    labels={'day_of_week': 'Day of Week', 'count': 'Count'},
                    color_discrete_map={
                        'Access-Accept': '#2E8B57',
                        'Access-Reject': '#DC143C'
                    }
                )
                fig_dow.update_xaxes(tickangle=45)
                st.plotly_chart(fig_dow, use_container_width=True)
        
        # Daily trend
        if 'date' in auth_df.columns:
            daily_data = auth_df.groupby(['date', 'result']).size().reset_index(name='count')
            fig_daily = px.line(
                daily_data,
                x='date',
                y='count',
                color='result',
                title="Daily Authentication Trend",
                labels={'date': 'Date', 'count': 'Count'},
                color_discrete_map={
                    'Access-Accept': '#2E8B57',
                    'Access-Reject': '#DC143C'
                }
            )
            st.plotly_chart(fig_daily, use_container_width=True)
    
    # Failure analysis
    if 'reason' in auth_df.columns and auth_df['reason'].notna().sum() > 0:
        st.subheader("🚫 Failure Analysis")
        failed_df = auth_df[auth_df['result'] == 'Access-Reject']
        if not failed_df.empty and failed_df['reason'].notna().sum() > 0:
            reason_counts = failed_df['reason'].value_counts().head(10)
            fig_reasons = px.bar(
                x=reason_counts.values,
                y=reason_counts.index,
                orientation='h',
                title="Top 10 Rejection Reasons",
                labels={'x': 'Count', 'y': 'Reason'}
            )
            fig_reasons.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_reasons, use_container_width=True)
    
    # Data table
    

def create_fticks_dashboard(fticks_df: pd.DataFrame):
    """Create F-TICKS dashboard tab"""



    #Data Table
    st.subheader("📋 Recent F-TICKS Records")
    display_cols = ['timestamp', 'result', 'realm', 'visinst', 'viscountry', 'federation']
    available_cols = [col for col in display_cols if col in fticks_df.columns]
    
    if available_cols:
        st.dataframe(
            fticks_df[available_cols].sort_values('timestamp', ascending=True),
            use_container_width=True
        )




    st.header("📊 F-TICKS Analysis")
    
    if fticks_df.empty:
        st.warning("No F-TICKS data found in the logs.")
        st.info("Expected format: Lines containing 'F-TICKS' with REALM, VISINST, and RESULT fields")
        return
    
    # Metrics overview
    DashboardComponents.create_metric_cards(fticks_df, 'result')
    
    # Sidebar filters
    st.sidebar.header("🔍 F-TICKS Filters")
    
    # Date range filter
    if 'date' in fticks_df.columns and not fticks_df['date'].isna().all():
        date_range = st.sidebar.date_input(
            "Date Range",
            value=(fticks_df['date'].min(), fticks_df['date'].max()),
            min_value=fticks_df['date'].min(),
            max_value=fticks_df['date'].max(),
            key="fticks_date"
        )
        
        if isinstance(date_range, tuple) and len(date_range) == 2:
            start_date = pd.to_datetime(date_range[0]).date()
            end_date = pd.to_datetime(date_range[1]).date()
            fticks_df = fticks_df[
                (fticks_df['date'] >= start_date) & 
                (fticks_df['date'] <= end_date)
            ]
    
    # Result filter
    if 'result' in fticks_df.columns:
        results = ['All'] + sorted(fticks_df['result'].unique().tolist())
        selected_result = st.sidebar.selectbox("Result Status", results, key="fticks_result")
        if selected_result != 'All':
            fticks_df = fticks_df[fticks_df['result'] == selected_result]
    
    # Realm filter
    if 'realm' in fticks_df.columns:
        realms = ['All'] + sorted([r for r in fticks_df['realm'].unique().tolist() if r])
        selected_realm = st.sidebar.selectbox("Realm", realms[:50])  # Limit to avoid overwhelming UI
        if selected_realm != 'All':
            fticks_df = fticks_df[fticks_df['realm'] == selected_realm]
    
    # Institution filter
    if 'visinst' in fticks_df.columns:
        institutions = ['All'] + sorted(fticks_df['visinst'].unique().tolist())
        selected_institution = st.sidebar.selectbox("Institution", institutions[:50])
        if selected_institution != 'All':
            fticks_df = fticks_df[fticks_df['visinst'] == selected_institution]
    
    if fticks_df.empty:
        st.warning("No data matches the selected filters.")
        return
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Result distribution
        if 'result' in fticks_df.columns:
            result_counts = fticks_df['result'].value_counts()
            colors = ['#2E8B57' if x == 'OK' else '#DC143C' if x == 'FAIL' else '#FFB347' for x in result_counts.index]
            fig_results = px.pie(
                values=result_counts.values,
                names=result_counts.index,
                title="F-TICKS Result Distribution",
                color_discrete_sequence=colors
            )
            st.plotly_chart(fig_results, use_container_width=True)
    
    with col2:
        # Top institutions
        if 'visinst' in fticks_df.columns:
            inst_counts = fticks_df['visinst'].value_counts().head(10)
            fig_inst = px.bar(
                x=inst_counts.values,
                y=inst_counts.index,
                orientation='h',
                title="Top 10 Visiting Institutions",
                labels={'x': 'Count', 'y': 'Institution'}
            )
            fig_inst.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_inst, use_container_width=True)
    
    # Geographic and realm analysis
    col1, col2 = st.columns(2)
    
    with col1:
        # Country distribution
        if 'viscountry' in fticks_df.columns:
            country_counts = fticks_df['viscountry'].value_counts().head(15)
            fig_country = px.bar(
                x=country_counts.index,
                y=country_counts.values,
                title="Top Countries by Usage",
                labels={'x': 'Country', 'y': 'Count'}
            )
            fig_country.update_xaxes(tickangle=45)
            st.plotly_chart(fig_country, use_container_width=True)
    
    with col2:
        # Top realms (only non-empty ones)
        if 'realm' in fticks_df.columns:
            realm_counts = fticks_df[fticks_df['realm'].notna() & (fticks_df['realm'] != '')]['realm'].value_counts().head(10)
            if not realm_counts.empty:
                fig_realm = px.bar(
                    x=realm_counts.values,
                    y=realm_counts.index,
                    orientation='h',
                    title="Top 10 Realms",
                    labels={'x': 'Count', 'y': 'Realm'}
                )
                fig_realm.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig_realm, use_container_width=True)
            else:
                st.info("No realm data available")
    
    # Time series analysis
    if 'timestamp' in fticks_df.columns and not fticks_df['timestamp'].isna().all():
        st.subheader("📈 Time Series Analysis (F-TICKS)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Hourly distribution
            if 'hour' in fticks_df.columns:
                hourly_data = fticks_df.groupby(['hour', 'result']).size().reset_index(name='count')
                fig_hourly = px.bar(
                    hourly_data,
                    x='hour',
                    y='count',
                    color='result',
                    title="Hourly F-TICKS Distribution",
                    labels={'hour': 'Hour of Day', 'count': 'Count'}
                )
                st.plotly_chart(fig_hourly, use_container_width=True)
        
        with col2:
            # Daily trend
            if 'date' in fticks_df.columns:
                daily_data = fticks_df.groupby(['date', 'result']).size().reset_index(name='count')
                fig_daily = px.line(
                    daily_data,
                    x='date',
                    y='count',
                    color='result',
                    title="Daily F-TICKS Trend",
                    labels={'date': 'Date', 'count': 'Count'}
                )
                st.plotly_chart(fig_daily, use_container_width=True)
    
    # Federation analysis
    if 'federation' in fticks_df.columns and not fticks_df['federation'].isna().all():
        st.subheader("🌐 Federation Analysis")
        federation_counts = fticks_df['federation'].value_counts()
        fig_fed = px.bar(
            x=federation_counts.index,
            y=federation_counts.values,
            title="Usage by Federation",
            labels={'x': 'Federation', 'y': 'Count'}
        )
        st.plotly_chart(fig_fed, use_container_width=True)
    
    # Data table
    

def create_system_dashboard(other_df: pd.DataFrame):
    """Create system logs dashboard tab"""
    st.header("🔧 System Logs Analysis")
    
    if other_df.empty:
        st.warning("No system log data found.")
        return
    
    # Basic metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total System Messages", f"{len(other_df):,}")
    with col2:
        if 'date' in other_df.columns and not other_df['date'].isna().all():
            unique_days = other_df['date'].nunique()
            st.metric("Days with Activity", f"{unique_days:,}")
    with col3:
        # Common message types
        if 'message' in other_df.columns:
            error_count = other_df['message'].str.contains('error|Error|ERROR', case=False, na=False).sum()
            st.metric("Error Messages", f"{error_count:,}")
    
    # Message analysis
    if len(other_df) > 0 and 'message' in other_df.columns:
        # Extract message types
        other_df['message_type'] = other_df['message'].str.extract(r'^([^:]+):?').fillna('other')
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Message type distribution
            msg_type_counts = other_df['message_type'].value_counts().head(10)
            fig_msg_types = px.bar(
                x=msg_type_counts.values,
                y=msg_type_counts.index,
                orientation='h',
                title="Top 10 Message Types",
                labels={'x': 'Count', 'y': 'Message Type'}
            )
            fig_msg_types.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_msg_types, use_container_width=True)
        
        with col2:
            # Timeline
            if not other_df['timestamp'].isna().all():
                daily_counts = other_df.groupby('date').size().reset_index(name='count')
                fig_timeline = px.line(
                    daily_counts,
                    x='date',
                    y='count',
                    title="Daily System Message Count",
                    labels={'date': 'Date', 'count': 'Messages'}
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
    
    # Recent messages
    

def main():
    """Main Streamlit application"""
    st.set_page_config(
        page_title="Eduroam Log Analytics",
        page_icon="📊",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("📊 Eduroam Log Analytics Dashboard")
    st.markdown("---")
    
    # File info and refresh
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        log_file = "logs.txt"
        if os.path.exists(log_file):
            file_size = os.path.getsize(log_file) / (1024 * 1024)  # MB
            mod_time = datetime.fromtimestamp(os.path.getmtime(log_file))
            st.info(f"📁 Log file: {log_file} ({file_size:.1f} MB, modified: {mod_time.strftime('%Y-%m-%d %H:%M:%S')})")
        else:
            st.error(f"❌ Log file '{log_file}' not found!")
            st.stop()
    
    with col3:
        if st.button("🔄 Refresh Data", help="Reload data from log file"):
            st.cache_data.clear()
            st.rerun()
    
    # Initialize parser and load data
    parser = EduroamLogParser(log_file)
    
    with st.spinner("Parsing log files..."):
        auth_df, fticks_df, other_df = parser.parse_logs()
    
    # Summary statistics at the top
    if not auth_df.empty or not fticks_df.empty or not other_df.empty:
        st.subheader("📈 Overview")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Authentication Records", f"{len(auth_df):,}")
        with col2:
            st.metric("F-TICKS Records", f"{len(fticks_df):,}")
        with col3:
            st.metric("System Messages", f"{len(other_df):,}")
        with col4:
            total_records = len(auth_df) + len(fticks_df) + len(other_df)
            st.metric("Total Log Entries", f"{total_records:,}")
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["🔐 Authentication Logs", "📊 F-TICKS Logs", "🔧 System Logs"])
    
    with tab1:
        create_auth_dashboard(auth_df)
    
    with tab2:
        create_fticks_dashboard(fticks_df)
    
    with tab3:
        create_system_dashboard(other_df)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "💡 **About this Dashboard:**\n"
        "- **Authentication Logs:** Shows user authentication attempts (Access-Accept/Access-Reject)\n"
        "- **F-TICKS Logs:** Shows federation usage statistics and roaming patterns\n"
        "- **System Logs:** Shows other system messages and errors\n\n"
        "🔄 Click 'Refresh Data' to reload the latest log entries."
    )

if __name__ == "__main__":
    main()