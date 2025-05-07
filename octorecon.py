#!/usr/bin/env python3
"""
Workplace Browser History Analyzer
Analyzes Brave browser history for workplace investigation
"""

import csv
import argparse
import datetime
import pytz
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse, unquote
import numpy as np
import re 
import os
import html
import traceback

class BrowserHistoryAnalyzer:
    def __init__(self, start_time, end_time, work_days, work_keywords=[], custom_categories_map=None):
        self.start_time = start_time
        self.end_time = end_time
        self.work_days = work_days
        self.work_keywords = [wk.lower() for wk in work_keywords if wk]
        self.custom_categories_map = custom_categories_map if custom_categories_map else {}
        
        self.aedt = pytz.timezone('Australia/Sydney')
        self.aest = pytz.timezone('Australia/Brisbane')
        
        self.COMMON_LEGIT_DOMAINS_WHITELIST = {
            "microsoft.com", "office.com", "live.com", "sharepoint.com", "outlook.com", "teams.microsoft.com",
            "google.com", "gmail.com", "drive.google.com", "docs.google.com", "googleusercontent.com", "googleapis.com",
            "apple.com", "icloud.com", "cdn-apple.com",
            "adobe.com", "adobelogin.com", "typekit.net", "creativecloud.adobe.com",
            "zoom.us", "slack.com", "slackb.com",
            "akamaihd.net", "cloudfront.net", "azureedge.net", "windowsupdate.com", "update.microsoft.com",
            "msftauth.net", "msidentity.com", "msn.com", "bing.com",
            "spiceworks.com", "github.com", "stackoverflow.com", "atlassian.net", "bitbucket.org", "trello.com", "jira.com",
            "docker.com", "npmjs.com", "pypi.org", "python.org",
            "paypal.com", "stripe.com", "xero.com", "myob.com",
            "netwrix.com", "enrolhq.com.au", "salesforce.com", "service-now.com",
        }
        self.COMMON_LEGIT_DOMAIN_PATTERNS = [
            r'\.gov\.au$', r'\.gov\.nz$', r'\.gov\.uk$', r'\.gov$', r'\.mil$',
            r'\.edu\.au$', r'\.edu$'
        ]

        self.patterns = { 
            'infrastructure_internal': [
                r'^192\.168\.\d{1,3}\.\d{1,3}$', r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                r'^172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}$', r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                r'^localhost$', 'fortinet', 'paloaltonetworks', 'cisco', 'meraki.com', 'sophos.com',
                'msftconnecttest.com', 'msedge.net', 'gvt1.com', 'gvt2.com', 
                'clientservices.googleapis.com', 'push.apple.com', 'setup.icloud.com',
                'activity.windows.com', 'settings-win.data.microsoft.com', 'v10.events.data.microsoft.com',
                'ctldl.windowsupdate.com', 
            ],
            'adult': [
                'pornhub', 'xvideos', 'xnxx', 'youporn', 'redtube', 'xhamster',
                'brazzers', 'onlyfans', 'chaturbate', 'cam4', 'myfreecams', 'livejasmin', 'spankbang'
            ],
            'streaming': [
                'youtube', 'netflix', 'disneyplus.com', 'disney+', 'hulu', 'primevideo.com', 'amazon.com/gp/video', 
                'twitch.tv', 'vimeo', 'dailymotion', 'abc.net.au/iview',
                'sbs.com.au/ondemand', 'stan.com.au', 'binge.com.au', 'foxtel.com.au/foxtel-go', 'kayosports.com.au'
            ],
            'shopping': [
                'amazon', 'ebay', 'paypal', 'westfield', 'myer', 'davidjones.com',
                'bigw.com.au', 'target.com.au', 'kmart.com.au', 'woolworths.com.au', 'coles.com.au', 'jbhifi.com.au',
                'harveynorman.com.au', 'officeworks.com.au', 'catch.com.au', 'gumtree.com.au', 'facebook.com/marketplace', 
                'etsy.com', 'asos.com', 'shein.com', 'temu.com', 'aliexpress.com'
            ],
            'gaming': [
                'steampowered.com', 'steamcommunity.com', 'epicgames.com', 'origin.com','ea.com', 
                'battle.net', 'blizzard.com', 'ubisoftconnect.com', 'ubisoft.com', 'uplay.com',
                'gog.com', 'playstation.com', 'xbox.com', 'nintendo.com', 
                'discord.com', 'discordapp.com', 'roblox.com', 'minecraft.net',
                'reddit.com/r/gaming', 'gamefaqs.gamespot.com', 'ign.com', 'nexusmods.com', 'curseforge.com'
            ],
            'social_media': [
                'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'tiktok.com', 'snapchat.com', 'linkedin.com',
                'reddit.com', 
                'pinterest.com', 'tumblr.com', 'whatsapp.com', 'web.telegram.org', 'signal.org', 'threads.net'
            ],
            'news': [
                'abc.net.au/news', 'sbs.com.au/news', 'smh.com.au', 'theage.com.au', 
                'theaustralian.com.au', 'news.com.au', 'bbc.com/news', 'cnn.com',
                'reuters.com', 'apnews.com', 'theconversation.com', 'crikey.com.au', 'theguardian.com', 'nytimes.com'
            ]
        }
        
        self.inappropriate_keywords = {
            'fuck', 'shit', 'cunt', 'bastard', 'wanker', 'twat', 'arsehole', 'dickhead', 'motherfucker',
            'porn', 'xxx', 'sex', 'nude', 'naked', 'erotic', 'nsfw', 
            'masturbat', 'orgasm', 'cumshot', 'dildo', 'vibrator', 'fetish', 'bdsm', 'hentai', 'milf', 'teenporn', 'shemale',
            'escort', 'brothel', 'hooker', 'prostitute',
            'betting', 'poker', 'casino', 'gambling', 'sportsbet', 'betfair', 'bet365', 'neds', 'ladbrokes', 'punt', 'bookmaker', 'slotmachine'
        }
        
    def parse_timestamp(self, timestamp_str):
        try:
            if pd.isna(timestamp_str): return None
            timestamp = float(str(timestamp_str))
            WINDOWS_EPOCH_OFFSET = 11644473600
            unix_timestamp = (timestamp / 1000000) - WINDOWS_EPOCH_OFFSET
            if timestamp == 0: return None
            dt = datetime.datetime.fromtimestamp(unix_timestamp, tz=datetime.timezone.utc)
            try: dt_aware = dt.astimezone(self.aedt)
            except: dt_aware = dt.astimezone(self.aest)
            return dt_aware
        except: return None 
    
    def get_main_domain(self, netloc):
        if not netloc: return ""
        parts = netloc.split('.')
        if len(parts) > 2:
            if parts[-2].lower() in ('com', 'co', 'org', 'net', 'gov', 'edu', 'ac', 'net') and len(parts[-1]) == 2: 
                return '.'.join(parts[-3:]).lower()
            return '.'.join(parts[-2:]).lower() 
        return netloc.lower() 

    def categorize_url(self, url):
        if pd.isna(url) or not url: return 'other'
        try: decoded_url = unquote(url)
        except Exception: decoded_url = url
        url_lower = decoded_url.lower()
        parsed_url = urlparse(decoded_url)
        domain_full = parsed_url.netloc.lower()
        main_domain = self.get_main_domain(parsed_url.netloc)
        path_query_lower = (parsed_url.path + ('?' if parsed_url.query else '') + parsed_url.query).lower()

        if self.custom_categories_map:
            sorted_custom_keywords = sorted(self.custom_categories_map.keys(), key=len, reverse=True)
            for custom_keyword in sorted_custom_keywords:
                pattern = r'(?:^|[\W_])' + re.escape(custom_keyword) + r'(?:$|[\W_])'
                if re.search(pattern, url_lower, re.IGNORECASE):
                    return self.custom_categories_map[custom_keyword].lower()

        is_whitelisted_domain = False
        if main_domain in self.COMMON_LEGIT_DOMAINS_WHITELIST:
            is_whitelisted_domain = True
        if not is_whitelisted_domain:
            for legit_pattern in self.COMMON_LEGIT_DOMAIN_PATTERNS: 
                if re.search(legit_pattern, domain_full):
                    is_whitelisted_domain = True
                    break
        
        if is_whitelisted_domain:
            for keyword in self.work_keywords: 
                if keyword in domain_full or keyword in path_query_lower: return 'work'
            for legit_pattern in self.COMMON_LEGIT_DOMAIN_PATTERNS: 
                 if re.search(legit_pattern, domain_full): return 'infrastructure_internal'

        sorted_work_keywords = sorted(self.work_keywords, key=len, reverse=True)
        for keyword in sorted_work_keywords:
            pattern = r'(?:^|[\W_])' + re.escape(keyword) + r'(?:$|[\W_])' 
            if re.search(pattern, url_lower, re.IGNORECASE):
                return 'work'

        category_check_order = ['infrastructure_internal', 'adult', 'streaming', 'shopping', 'gaming', 'social_media', 'news']
        for category_name in category_check_order:
            patterns_for_category = self.patterns.get(category_name, [])
            for pattern_item in patterns_for_category: 
                is_regex = pattern_item.startswith(r'^') and pattern_item.endswith(r'$')
                if is_regex: 
                    if re.match(pattern_item, domain_full): return category_name
                else: 
                    if pattern_item in domain_full: return category_name
                    if category_name not in ['infrastructure_internal', 'adult'] and pattern_item in path_query_lower:
                         return category_name
        return 'other'

    def is_inappropriate(self, url, url_category, domain_full, main_domain):
        if pd.isna(url) or not url: return False, None
        if url_category in ['work', 'infrastructure_internal']: return False, None
        if main_domain in self.COMMON_LEGIT_DOMAINS_WHITELIST: return False, None
        for legit_pattern in self.COMMON_LEGIT_DOMAIN_PATTERNS:
            if re.search(legit_pattern, domain_full): return False, None
        
        try: decoded_url = unquote(url)
        except Exception: decoded_url = url
        url_lower = decoded_url.lower()

        for keyword in self.inappropriate_keywords:
            pattern = r'(?:^|[\W_])' + re.escape(keyword) + r'(?:$|[\W_])'
            if re.search(pattern, url_lower, re.IGNORECASE):
                 return True, keyword
        return False, None
    
    def is_work_hours(self, dt):
        if dt is None or pd.isna(dt): return False
        day_of_week_num = dt.weekday()
        day_map_to_int = {'M': 0, 'T': 1, 'W': 2, 'Th': 3, 'F': 4, 'Sa': 5, 'Su': 6}
        work_day_numbers = [day_map_to_int[d_abbr] for d_abbr in self.work_days if d_abbr in day_map_to_int]
        if day_of_week_num not in work_day_numbers: return False
        
        time_obj = dt.time()
        time_formats = ["%H:%M", "%I:%M%p", "%H", "%I%p"] 
        parsed_start_time, parsed_end_time = None, None
        for fmt in time_formats:
            try:
                if parsed_start_time is None:
                    parsed_start_time = datetime.datetime.strptime(self.start_time.upper().replace(" ", ""), fmt).time()
            except ValueError: pass
            try:
                if parsed_end_time is None:
                    parsed_end_time = datetime.datetime.strptime(self.end_time.upper().replace(" ", ""), fmt).time()
            except ValueError: pass
        
        if parsed_start_time is None or parsed_end_time is None: return False 
        
        if parsed_end_time <= parsed_start_time: 
            return time_obj >= parsed_start_time or time_obj < parsed_end_time
        else: 
            return parsed_start_time <= time_obj < parsed_end_time
    
    def analyze_csv(self, csv_file):
        try:
            df = pd.read_csv(csv_file, on_bad_lines='skip', low_memory=False)
            required_columns = ['url', 'last_visit_time']
            if not all(col in df.columns for col in required_columns):
                print(f"Error: CSV must contain 'url' and 'last_visit_time'. Found: {list(df.columns)}")
                return pd.DataFrame()
            
            data = []
            for index, row in df.iterrows():
                dt = self.parse_timestamp(row['last_visit_time'])
                if dt is None: continue
                
                url = str(row.get('url', '')) 
                if not url or pd.isna(url): url = "Unknown_URL"

                parsed_url_for_domain = urlparse(url)
                domain_full_for_check = parsed_url_for_domain.netloc.lower()
                main_domain_for_check = self.get_main_domain(parsed_url_for_domain.netloc)
                url_category = self.categorize_url(url) 
                is_inappropriate_flag, inappropriate_keyword_reason = self.is_inappropriate(url, url_category, domain_full_for_check, main_domain_for_check)
                work_hours_flag = self.is_work_hours(dt)
                
                data.append({
                    'visit_id': row.get('id', index), 'url': url,
                    'domain': domain_full_for_check if url != "Unknown_URL" else "Unknown_Domain",
                    'visit_count': int(row.get('visit_count', 0)) if pd.notna(row.get('visit_count')) else 0,
                    'typed_count': int(row.get('typed_count', 0)) if pd.notna(row.get('typed_count')) else 0,
                    'datetime': dt, 'hour': dt.hour, 'weekday': dt.strftime('%A'),
                    'date': dt.date(), 'category': url_category, 
                    'inappropriate': is_inappropriate_flag,
                    'inappropriate_reason': inappropriate_keyword_reason,
                    'work_hours': work_hours_flag
                })
            
            if not data: return pd.DataFrame()
            result_df = pd.DataFrame(data)
            result_df['datetime'] = pd.to_datetime(result_df['datetime'], errors='coerce')
            result_df.dropna(subset=['datetime'], inplace=True)
            print(f"Successfully processed {len(result_df)} records from {len(df)} initial rows.")
            return result_df
        except Exception as e:
            print(f"Critical error reading or processing CSV file '{csv_file}': {e}")
            traceback.print_exc()
            return pd.DataFrame()

    def generate_report(self, df, output_file='browser_history_report.html'):
        if df.empty:
            print("Cannot generate report: No data to analyze")
            return None
        
        try: plt.style.use('seaborn-v0_8-darkgrid')
        except: plt.style.use('ggplot')

        fig, axes = plt.subplots(3, 3, figsize=(22, 26)) 
        fig.suptitle('Browser History Analysis', fontsize=22, y=1.01)
        
        chart_plot_config = [
            (
                lambda data, ax, **kwargs: ax.pie(data.values, labels=['Work Hours' if idx else 'Non-Work Hours' for idx in data.index], colors=['lightgreen' if idx else 'lightcoral' for idx in data.index], autopct='%1.1f%%', startangle=90),
                df['work_hours'].value_counts(), (0,0), 'Activity: Work vs Non-Work Hours', None, None, {'axis_equal': True}
            ),
            (
                lambda data, ax, **kwargs: sns.barplot(x=data.index, y=data.values, ax=ax, hue=data.index, palette="viridis", legend=False, **kwargs.get('sns_params',{})),
                df['category'].value_counts(), (0,1), 'Website Categories Accessed', None, 'Visits', {'xtick_rotation': 45}
            ),
            (
                lambda data, ax, **kwargs: ax.pie(data.values, labels=['Inappropriate' if idx else 'Appropriate' for idx in data.index], colors=['red' if idx else 'lightblue' for idx in data.index], autopct='%1.1f%%', startangle=90),
                df['inappropriate'].value_counts(), (0,2), 'Inappropriate Content Detection', None, None, {'axis_equal': True}
            ),
            (
                lambda data, ax, **kwargs: sns.barplot(x=data.index, y=data.values, ax=ax, hue=data.index, color="skyblue", legend=False, **kwargs.get('sns_params',{})), 
                df.groupby('hour').size().reindex(range(24), fill_value=0), (1,0), 'Activity by Hour of Day', 'Hour (0-23)', 'Visits', {}
            ),
            (
                lambda data, ax, **kwargs: sns.barplot(x=data.index, y=data.values, ax=ax, hue=data.index, palette="Spectral", legend=False, **kwargs.get('sns_params',{})),
                df.groupby('weekday').size().reindex(['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'], fill_value=0), (1,1), 'Activity by Day of Week', None, 'Visits', {'xtick_rotation': 45}
            ),
            (
                lambda data, ax, **kwargs: sns.barplot(y=data.index, x=data.values, ax=ax, hue=data.index, palette="coolwarm", orient='h', legend=False, **kwargs.get('sns_params',{})),
                df['domain'][df['domain'].str.lower() != 'unknown_domain'].value_counts().nlargest(10), (1,2), 'Top 10 Visited Domains', 'Visits', None, {'ytick_fontsize': 10}
            ),
            (
                lambda data, ax, **kwargs: sns.barplot(x=data.index, y=data.values, ax=ax, hue=data.index, color="orange", legend=False, **kwargs.get('sns_params',{})), 
                df[df['category'] == 'streaming'].groupby('hour').size().reindex(range(24), fill_value=0), (2,0), 'Streaming Usage by Hour', 'Hour (0-23)', 'Visits', {}
            ),
            ( 
                lambda data, ax, **kwargs: data.plot(kind='bar', ax=ax, stacked=False, **kwargs.get('plot_params',{})), 
                df.groupby(['category', 'work_hours']).size().unstack(fill_value=0).rename(columns={True: 'Work Hours', False: 'Non-Work Hours'}), (2,1), 'Categories: Work vs Non-Work', None, 'Visits', {'xtick_rotation': 45, 'legend_title': 'Period'}
            ),
            (
                lambda data, ax, **kwargs: data.plot(kind='line', ax=ax, marker='o', color='red', **kwargs.get('plot_params',{})),
                df[df['inappropriate']].set_index('datetime').resample('D').size() if not df[df['inappropriate']].empty else pd.Series(dtype=int), (2,2), 'Inappropriate Content Over Time', 'Date', 'Count', {'xtick_rotation': 45}
            )
        ]

        for plot_func, data_series, ax_idx, title, xlabel, ylabel, params in chart_plot_config:
            current_ax = axes[ax_idx]
            has_data = False
            if isinstance(data_series, pd.DataFrame):
                if not data_series.empty and not (data_series.sum(axis=0).eq(0).all() and data_series.sum(axis=1).eq(0).all()):
                    has_data = True
            elif isinstance(data_series, pd.Series):
                if not data_series.empty and data_series.sum() > 0: has_data = True
            
            if has_data:
                plot_func(data_series, current_ax, **params)
            else:
                current_ax.text(0.5, 0.5, "No Data Available", ha="center", va="center", fontsize=10, color='grey')

            current_ax.set_title(title, fontsize=14)
            if xlabel: current_ax.set_xlabel(xlabel, fontsize=12)
            if ylabel: current_ax.set_ylabel(ylabel, fontsize=12)
            
            if has_data: 
                if params.get('xtick_rotation'): 
                    plt.setp(current_ax.get_xticklabels(), rotation=params['xtick_rotation'], ha='right', fontsize=10)
                if params.get('ytick_fontsize'): 
                    plt.setp(current_ax.get_yticklabels(), fontsize=params['ytick_fontsize'])
                if params.get('axis_equal'): 
                    current_ax.axis('equal')
                if params.get('legend_title') and hasattr(current_ax, 'legend') and current_ax.get_legend() is not None:
                     current_ax.legend(title=params['legend_title'], fontsize=10)


        plt.tight_layout(rect=[0, 0, 1, 0.98])
        charts_image_path = 'browser_analysis_charts.png'
        try: plt.savefig(charts_image_path, dpi=300, bbox_inches='tight')
        except Exception as e: print(f"Error saving charts: {e}"); charts_image_path = None
        plt.close(fig)
        
        min_date = df['datetime'].min(); max_date = df['datetime'].max()
        min_date_str = min_date.strftime('%Y-%m-%d %H:%M:%S %Z') if pd.notna(min_date) else "N/A"
        max_date_str = max_date.strftime('%Y-%m-%d %H:%M:%S %Z') if pd.notna(max_date) else "N/A"
        total_s, work_h_s, inapp_s = len(df), df['work_hours'].sum(), df['inappropriate'].sum()
        stream_s = (df['category'] == 'streaming').sum() if 'category' in df.columns else 0
        game_s = (df['category'] == 'gaming').sum() if 'category' in df.columns else 0
        shop_s = (df['category'] == 'shopping').sum() if 'category' in df.columns else 0
        work_h_p = (work_h_s / total_s * 100) if total_s > 0 else 0
        non_work_h_s = total_s - work_h_s; non_work_h_p = (non_work_h_s / total_s * 100) if total_s > 0 else 0

        def generate_table_rows_html(dataframe, columns_map, sort_by_col='datetime', ascending_sort=False):
            html_rows = ""
            if dataframe.empty:
                return f"<tr><td colspan='{len(columns_map)}' style='text-align:center; padding:10px;'>No data for this section.</td></tr>"
            
            df_to_sort = dataframe.copy() 
            if sort_by_col not in df_to_sort.columns:
                sorted_df = df_to_sort
            else:
                sorted_df = df_to_sort.sort_values(by=sort_by_col, ascending=ascending_sort)

            for _, row in sorted_df.iterrows():
                html_rows += "<tr>"
                for col_key in columns_map.keys(): 
                    val = row.get(col_key, "N/A")
                    display_val = ""; td_attrs = ""
                    if col_key == 'datetime' and pd.notna(val): 
                        display_val = val.strftime('%Y-%m-%d %H:%M:%S %Z')
                    elif col_key == 'url' and val != "N/A":
                        escaped_url = html.escape(str(val))
                        display_val = f'<a href="{escaped_url}" target="_blank" title="{escaped_url}">{escaped_url[:80]}{"..." if len(escaped_url)>80 else ""}</a>'
                    elif col_key == 'work_hours': 
                        status = "Yes" if val else "No"
                        display_val = status
                        if val and row.get('inappropriate', False): 
                            td_attrs = 'class="warning-text"' 
                    elif col_key == 'inappropriate_reason': 
                        display_val = html.escape(str(val)) if pd.notna(val) else "N/A"
                    else: 
                        display_val = html.escape(str(val))
                    html_rows += f"<td {td_attrs}>{display_val}</td>"
                html_rows += "</tr>\n"
            return html_rows

        inappropriate_cols_map = {'datetime':'DateTime', 'url':'URL', 'category':'Assigned Category', 'inappropriate_reason':'Reason (Keyword)', 'work_hours':'During Work Hours'}
        activity_cols_map = {'datetime':'DateTime', 'url':'URL', 'visit_count':'Visit Count', 'work_hours': 'During Work Hours'} 
        # THIS IS WHERE non_work_activity_cols_map IS NOW DEFINED CORRECTLY BEFORE USE
        non_work_activity_cols_map = {'datetime':'DateTime', 'url':'URL', 'visit_count':'Visit Count'} 

        all_categories_in_data = df['category'].unique().tolist()
        non_work_sub_tab_categories = [
            cat for cat in all_categories_in_data 
            if cat not in ['work', 'infrastructure_internal', 'other'] and not pd.isna(cat)
        ]
        # Ensure 'other' is last if present and not already included
        if 'other' in all_categories_in_data and 'other' not in non_work_sub_tab_categories :
            non_work_sub_tab_categories.append('other')


        html_content = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Browser History Report</title>
        <style>
            body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; padding:0; background-color: #f0f2f5; color: #333; }}
            .report-container {{ max-width: 90%; margin: 20px auto; background: #fff; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); border-radius: 8px; }}
            .header {{ text-align: center; padding-bottom: 20px; border-bottom: 2px solid #007bff; margin-bottom:25px; }}
            .header h1 {{ color: #0056b3; margin-top:0; font-weight:600;}} .header p {{font-size:0.95em; color:#555;}}
            .main-tab-buttons {{ display: flex; flex-wrap: wrap; border-bottom: 1px solid #dee2e6; margin-bottom:20px; }}
            .main-tab-buttons button {{ background-color: #f8f9fa; color:#0056b3; flex-grow: 1; border: 1px solid transparent; border-bottom: none; outline: none; cursor: pointer; padding: 12px 15px; transition: background-color 0.3s, color 0.3s, border-color 0.3s; font-size: 1em; font-weight:500; margin-right: 2px; border-radius: 4px 4px 0 0; }}
            .main-tab-buttons button:hover {{ background-color: #e9ecef; }}
            .main-tab-buttons button.active {{ background-color: #007bff; color: white; border-color: #007bff #007bff #fff; }}
            .main-tab-content {{ display: none; padding: 15px; border: 1px solid #dee2e6; border-top: none; animation: fadeEffect 0.4s; background-color:#fff; border-radius: 0 0 4px 4px;}}
            .sub-tab-buttons {{ display: flex; flex-wrap: wrap; border-bottom: 1px solid #ccc; margin-bottom: 10px; margin-top: 5px; }}
            .sub-tab-buttons button {{ background-color: #eef; color:#0056b3; border: none; outline: none; cursor: pointer; padding: 10px 15px; transition: 0.3s; font-size: 0.95em; margin-right:1px; border-radius: 3px 3px 0 0; margin-bottom: 2px;}}
            .sub-tab-buttons button:hover {{ background-color: #dde; }}
            .sub-tab-buttons button.active {{ background-color: #007bff; color: white; }}
            .sub-tab-content {{ display: none; padding: 10px 0; }} 
            @keyframes fadeEffect {{ from {{opacity: 0; transform: translateY(10px);}} to {{opacity: 1; transform: translateY(0px);}} }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 15px; font-size: 0.9em; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
            th, td {{ border: 1px solid #e9ecef; padding: 10px 12px; text-align: left; word-break: break-word; }}
            th {{ background-color: #007bff; color: white; font-weight:600; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }} tr:hover {{ background-color: #e9ecef; }}
            .summary-box {{ background-color: #e7f3fe; border-left: 4px solid #007bff; padding: 15px 20px; margin: 20px 0; border-radius: 4px; }}
            .summary-box h2 {{margin-top:0; color: #0056b3;}} .summary-box ul {{ list-style-type: none; padding-left: 0; }} .summary-box li {{ margin-bottom: 10px; font-size: 0.95em; }}
            .warning-text {{ color: #d93025; font-weight: bold; }}
            .chart-container img {{ max-width: 100%; height: auto; border: 1px solid #dee2e6; margin-top:15px; border-radius:4px; }}
            .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 0.85em; color: #6c757d; }}
            h2 {{color: #0056b3; margin-top:0; border-bottom: 1px solid #eee; padding-bottom:8px;}} h4 {{color: #333; margin-top:20px; margin-bottom: 5px;}}
        </style>
        </head><body><div class="report-container">
            <div class="header"><h1>Workplace Browser History Analysis</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Analysis Period: {min_date_str} to {max_date_str}</p>
                <p>Work Hours: {self.start_time} - {self.end_time} ({', '.join(self.work_days)})</p>
            </div>

            <div class="main-tab-buttons">
                <button class="main-tab-button" onclick="openMainTab(event, 'Summary')" data-main-tabtarget="Summary">Executive Summary</button>
                <button class="main-tab-button" onclick="openMainTab(event, 'Visuals')" data-main-tabtarget="Visuals">Visual Analysis</button>
                <button class="main-tab-button" onclick="openMainTab(event, 'WorkActivity')" data-main-tabtarget="WorkActivity">Work Activity</button>
                <button class="main-tab-button" onclick="openMainTab(event, 'Inappropriate')" data-main-tabtarget="Inappropriate">Inappropriate Content</button>
                <button class="main-tab-button" onclick="openMainTab(event, 'NonWork')" data-main-tabtarget="NonWork">Non-Work Activity (Work Hours)</button>
                <button class="main-tab-button" onclick="openMainTab(event, 'Productivity')" data-main-tabtarget="Productivity">Productivity Indicators</button>
            </div>

            <div id="Summary" class="main-tab-content"><div class="summary-box"><h2>Executive Summary</h2><ul>
                <li>Total browsing sessions analyzed: {total_s}</li>
                <li>Activity during work hours: {work_h_s} ({work_h_p:.1f}%)</li>
                <li>Activity outside work hours: {non_work_h_s} ({non_work_h_p:.1f}%)</li>
                <li>Potentially inappropriate content detected (post-filtering): {inapp_s} instances</li>
                <li>Streaming service usage (all hours): {stream_s} instances</li>
                <li>Gaming site access (all hours): {game_s} instances</li>
                <li>Shopping site access (all hours): {shop_s} instances</li>
            </ul></div><p>This report provides an automated analysis of browser history. All findings, especially those flagged as 'inappropriate', require careful manual review and contextual understanding before any conclusions are drawn. The tool uses keyword matching and categorization rules which may produce false positives or misclassifications.</p></div>

            <div id="Visuals" class="main-tab-content"><h2>Visual Analysis</h2><div class="chart-container">
                {f'<img src="{os.path.basename(charts_image_path)}" alt="Browser Analysis Charts">' if charts_image_path and os.path.exists(charts_image_path) else "<p><em>Charts image not available.</em></p>"}
            </div></div>

            <div id="WorkActivity" class="main-tab-content"><h2>Work-Related Activity</h2>
                <p>Browsing sessions categorized as 'work' based on provided keywords or custom rules.</p><table>
                <thead><tr>{''.join(f"<th>{v}</th>" for v in activity_cols_map.values())}</tr></thead><tbody>
                {generate_table_rows_html(df[df['category'] == 'work'], activity_cols_map)}
            </tbody></table></div>

            <div id="Inappropriate" class="main-tab-content"><h2>Potentially Inappropriate Content</h2>
                <p>URLs flagged based on keywords, after excluding 'work', 'infrastructure_internal', whitelisted domains, and common government/education domains. <strong>Manual verification is essential.</strong></p><table>
                <thead><tr>{''.join(f"<th>{v}</th>" for v in inappropriate_cols_map.values())}</tr></thead><tbody>
                {generate_table_rows_html(df[df['inappropriate']], inappropriate_cols_map)}
            </tbody></table></div>

            <div id="NonWork" class="main-tab-content"><h2>Non-Work Activity During Work Hours</h2>
                <div class="sub-tab-buttons">
        """
        for cat_name in non_work_sub_tab_categories:
            cat_id_safe = re.sub(r'\W+', '', cat_name) 
            html_content += f"""<button class="sub-tab-button nw-sub-button" onclick="openSubTab(event, 'NW_{cat_id_safe}', 'NonWorkSubTabs')" data-sub-tabtarget="NW_{cat_id_safe}">{cat_name.replace('_',' ').title()}</button>\n"""
        
        html_content += """</div>""" 
        
        for cat_name in non_work_sub_tab_categories:
            cat_id_safe = re.sub(r'\W+', '', cat_name)
            html_content += f"""<div id="NW_{cat_id_safe}" class="sub-tab-content NonWorkSubTabs"><h4>{cat_name.replace('_',' ').title()} During Work Hours</h4><table><thead><tr>{''.join(f"<th>{v}</th>" for v in non_work_activity_cols_map.values())}</tr></thead><tbody>
            {generate_table_rows_html(df[(df['category'] == cat_name) & (df['work_hours'])], non_work_activity_cols_map)}
            </tbody></table></div>\n"""

        html_content += """</div>""" 
            
        html_content += f"""
            <div id="Productivity" class="main-tab-content"><div class="summary-box"><h2>Productivity Indicators</h2><ul>"""
        
        non_work_cats_for_prod_indicator = [cat for cat in all_categories_in_data if cat not in ['work', 'infrastructure_internal']]
        non_work_browsing_wh = len(df[df['work_hours'] & df['category'].isin(non_work_cats_for_prod_indicator)]) if total_s > 0 and 'category' in df.columns else 0
        inapp_work_wh = len(df[df['work_hours'] & df['inappropriate']]) if total_s > 0 and 'inappropriate' in df.columns else 0
        non_work_browsing_wh_p = (non_work_browsing_wh / work_h_s * 100) if work_h_s > 0 else 0
        active_days_series = df.groupby('weekday').size(); active_days_str = ', '.join(active_days_series.nlargest(3).index.tolist()) if not active_days_series.empty else 'N/A'
        peak_hours_series = df.groupby('hour').size(); peak_hours_str = ', '.join(map(str, peak_hours_series.nlargest(3).index.tolist())) + ":00" if not peak_hours_series.empty else 'N/A'

        html_content += f"""
                <li>During work hours, approx. {non_work_browsing_wh} of {work_h_s} browsing sessions ({non_work_browsing_wh_p:.1f}%) were to sites categorized as non-work related.</li>
                <li>{inapp_work_wh} instances of potentially inappropriate content (post-filtering) were accessed during work hours.</li>
                <li>Most active browsing days: {active_days_str}</li>
                <li>Peak browsing hours (approx.): {peak_hours_str}</li>
            </ul></div>
            <h3>Recommendations</h3><ol>
                <li>Review findings with relevant stakeholders, emphasizing manual verification of flagged content.</li>
                <li>Reinforce company's Acceptable Use Policy (AUP).</li>
                <li>If clear misuse (post-verification) is confirmed, consider actions as per company policy.</li>
                <li>Regularly review and update categorization keywords, work-keywords, and domain whitelists in this script.</li>
            </ol></div>
            <div class="footer"><p><em>Confidential Report. All automated flags require manual verification.</em></p></div>
        </div> <!-- report-container -->
        <script>
            function openMainTab(evt, tabName) {{
                var i, tabcontent, tabbuttons;
                tabcontent = document.getElementsByClassName("main-tab-content");
                for (i = 0; i < tabcontent.length; i++) {{ tabcontent[i].style.display = "none"; }}
                tabbuttons = document.getElementsByClassName("main-tab-button");
                for (i = 0; i < tabbuttons.length; i++) {{ tabbuttons[i].className = tabbuttons[i].className.replace(" active", ""); }}
                var targetTab = document.getElementById(tabName);
                if (targetTab) {{ targetTab.style.display = "block"; }}
                
                if (evt && evt.currentTarget) {{ 
                    evt.currentTarget.className += " active"; 
                }} else if (tabName) {{ 
                    for (i = 0; i < tabbuttons.length; i++) {{
                        if (tabbuttons[i].getAttribute('data-main-tabtarget') === tabName) {{
                            tabbuttons[i].className += " active";
                            break;
                        }}
                    }}
                }}

                if (tabName === "NonWork") {{
                    var firstSubTabButton = document.querySelector('#NonWork .sub-tab-buttons .nw-sub-button'); 
                    if (firstSubTabButton) {{ 
                        var activeSubTab = document.querySelector('#NonWork .sub-tab-buttons .nw-sub-button.active');
                        if (!activeSubTab) {{
                           firstSubTabButton.click(); 
                        }} else {{ 
                           var subTargetId = activeSubTab.getAttribute('data-sub-tabtarget');
                           if (subTargetId) {{
                               var subTargetContent = document.getElementById(subTargetId);
                               if (subTargetContent) subTargetContent.style.display = "block";
                           }}
                        }}
                    }}
                }}
            }}
            function openSubTab(evt, tabName, subTabContainerClass) {{
                var i, tabcontent, tabbuttons;
                var parentMainTabContent = evt.currentTarget.closest('.main-tab-content');
                if (!parentMainTabContent) return; 

                tabcontent = parentMainTabContent.getElementsByClassName(subTabContainerClass); 
                for (i = 0; i < tabcontent.length; i++) {{ tabcontent[i].style.display = "none"; }}
                
                var parentSubTabButtonContainer = evt.currentTarget.closest('.sub-tab-buttons'); 
                if (parentSubTabButtonContainer) {{
                    tabbuttons = parentSubTabButtonContainer.getElementsByClassName("sub-tab-button");
                     for (i = 0; i < tabbuttons.length; i++) {{
                        tabbuttons[i].className = tabbuttons[i].className.replace(" active", "");
                    }}
                }}
               
                var targetSubTab = document.getElementById(tabName);
                if (targetSubTab) {{ targetSubTab.style.display = "block"; }}
                if (evt && evt.currentTarget) {{ evt.currentTarget.className += " active"; }}
            }}
            document.addEventListener('DOMContentLoaded', function() {{
                var firstMainTabButton = document.querySelector('.main-tab-buttons .main-tab-button');
                if (firstMainTabButton) {{
                    var firstMainTabTargetId = firstMainTabButton.getAttribute('data-main-tabtarget');
                    openMainTab(null, firstMainTabTargetId); 
                }}
            }});
        </script></body></html>"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f: f.write(html_content)
            return output_file
        except IOError as e:
            print(f"Error writing HTML report: {e}")
            return None

def parse_custom_categories_arg(cat_string):
    custom_map = {}
    if not cat_string: return custom_map
    pattern = re.compile(r'(.+?)\s*\(([^)]+)\)')
    items = cat_string.split(',')
    for item in items:
        item = item.strip()
        match = pattern.fullmatch(item) 
        if match:
            keyword = match.group(1).strip().lower() 
            category = match.group(2).strip().lower() 
            if keyword and category: custom_map[keyword] = category
            else: print(f"Warning: Could not parse custom category item: '{item}'. Skipping.")
        elif item: print(f"Warning: Custom category item '{item}' not in 'keyword(category)' format. Skipping.")
    return custom_map

def main():
    parser = argparse.ArgumentParser(
        description='Analyze browser history for workplace investigation. Ensure CSV has "url" and "last_visit_time" columns.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('csv_file', help='Path to CSV browser history file.')
    parser.add_argument('--starttime', default='09:00', help='Work start time (e.g., "09:00", "9am", "13"). Default: 09:00.')
    parser.add_argument('--endtime', default='17:00', help='Work end time (e.g., "17:00", "5pm", "17"). Default: 17:00.')
    parser.add_argument('--days', default='M,T,W,Th,F', help='Comma-separated work days (M,T,W,Th,F,Sa,Su). Default: M,T,W,Th,F.')
    parser.add_argument('--work-keywords', default='', 
                        help='Comma-separated keywords/domains considered work-related (e.g., "mycompany.com,jira,salesforce").')
    parser.add_argument('--custom-categories', default='',
                        help='User-defined categories. Format: "keyword1(categoryA),keyword with space(categoryB)".\nExample: --custom-categories "my internal app(work),company cars(auto)"')
    parser.add_argument('--output', default='browser_history_report.html', help='Output HTML file name.')
    parser.add_argument('--diagnose', action='store_true', help='Show timestamp/category diagnosis for first few CSV rows and exit.')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.csv_file):
        print(f"Error: CSV file '{args.csv_file}' not found."); return

    work_days_input = [day.strip().upper() for day in args.days.split(',')]
    valid_day_map = {'M': 'M', 'MON': 'M', 'TU': 'T', 'TUE':'T', 'T': 'T', 'W': 'W', 'WED':'W', 
                     'TH': 'Th', 'THU':'Th', 'F': 'F', 'FRI':'F', 'SA': 'Sa', 'SAT':'Sa', 'SU': 'Su', 'SUN':'Su'}
    work_days_list = []
    day_order_map = {day: i for i, day in enumerate(['M', 'T', 'W', 'Th', 'F', 'Sa', 'Su'])}
    for day_in in work_days_input:
        normalized_day = valid_day_map.get(day_in, None)
        if normalized_day: work_days_list.append(normalized_day)
        else: print(f"Warning: Work day '{day_in}' not recognized.")
    work_days_list = sorted(list(set(work_days_list)), key=lambda d: day_order_map.get(d, 99)) 
    if not work_days_list: print("Error: No valid work days provided."); return

    work_keywords_list = [keyword.strip().lower() for keyword in args.work_keywords.split(',') if keyword.strip()]
    custom_categories_map = parse_custom_categories_arg(args.custom_categories)
    if custom_categories_map: print(f"Using custom categories: {custom_categories_map}")

    analyzer = BrowserHistoryAnalyzer(args.starttime, args.endtime, work_days_list, work_keywords_list, custom_categories_map)

    if args.diagnose:
        print(f"Diagnosing CSV: '{args.csv_file}' (first 5 rows)...")
        try:
            df_diag = pd.read_csv(args.csv_file, nrows=20, on_bad_lines='skip', low_memory=False) 
            if df_diag.empty: print("Diagnostic CSV empty/unreadable."); return
            print(f"Columns: {list(df_diag.columns)}")
            if 'last_visit_time' in df_diag.columns and 'url' in df_diag.columns:
                print("\nSample Processing:")
                for i, row_diag in df_diag.head(5).iterrows():
                    ts_raw, url_raw = row_diag['last_visit_time'], str(row_diag.get('url','Unknown_URL'))
                    print(f"\n--- Row {i+1} ---\n  Raw URL: '{url_raw[:100]}{'...' if len(url_raw)>100 else ''}'\n  Raw Timestamp: '{ts_raw}'")
                    parsed_dt = analyzer.parse_timestamp(ts_raw)
                    print(f"    Parsed Timestamp: {parsed_dt.strftime('%Y-%m-%d %H:%M:%S %Z') if parsed_dt else 'Failed'}")
                    p_url = urlparse(url_raw); domain_f, main_d = p_url.netloc.lower(), analyzer.get_main_domain(p_url.netloc)
                    category = analyzer.categorize_url(url_raw)
                    is_inapp, reason = analyzer.is_inappropriate(url_raw, category, domain_f, main_d)
                    print(f"    Full Domain: '{domain_f}', Main Domain: '{main_d}'\n    Categorized as: '{category}'")
                    print(f"    Flagged Inappropriate: {'Yes (Reason: ' + reason + ')' if is_inapp else 'No'}")
            else: print("Error: 'last_visit_time' and/or 'url' columns NOT found.")
        except Exception as e: print(f"Error during diagnosis: {e}\n{traceback.format_exc()}"); return
        return 
    
    print(f"Analyzing history from '{args.csv_file}'...")
    analyzed_df = analyzer.analyze_csv(args.csv_file)
    if analyzed_df.empty: print("No data processed. Report skipped."); return
    
    print(f"Generating report to '{args.output}'...")
    output_filepath = analyzer.generate_report(analyzed_df, args.output)
    
    if output_filepath and os.path.exists(output_filepath):
        abs_path_report = os.path.abspath(output_filepath)
        print(f"\nReport: file://{abs_path_report.replace(os.sep, '/')}")
        if os.path.exists('browser_analysis_charts.png'): print(f"Charts: file://{os.path.abspath('browser_analysis_charts.png').replace(os.sep, '/')}")
        total, work_h = len(analyzed_df), analyzed_df['work_hours'].sum()
        print(f"\nSummary: Total Records: {total}, Work Hours Records: {work_h} ({(work_h/total*100) if total else 0:.1f}%)")
        print(f"Potentially Inappropriate (post-filtering): {analyzed_df['inappropriate'].sum()}")
    else: print("Failed to generate report.")

if __name__ == "__main__":
    main()
