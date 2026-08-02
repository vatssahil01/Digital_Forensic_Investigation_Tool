#!/usr/bin/env python
# coding: utf-8

# In[1]:


"""
Digital Forensic Investigation Tool
Compatible with Windows, macOS, and Linux
"""

import os
import sys
import hashlib
import json
import sqlite3
import shutil
from datetime import datetime,timedelta
from pathlib import Path
import platform
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter import font as tkfont
import threading
import queue
import re

class DigitalForensicTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensic Investigation Tool v2.0")
        self.root.geometry("1400x800")
        self.root.configure(bg='#2c3e50')

        # Set style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', background='#3498db', foreground='white', padding=10)
        self.style.configure('TLabel', background='#2c3e50', foreground='white')
        self.style.configure('TFrame', background='#2c3e50')

        # Variables
        self.current_os = platform.system()
        self.investigation_data = {}
        self.hash_queue = queue.Queue()
        self.results_queue = queue.Queue()

        # Create main container
        self.main_container = ttk.Frame(root)
        self.main_container.pack(fill='both', expand=True, padx=10, pady=10)

        # Header
        self.create_header()

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill='both', expand=True, pady=5)

        # Create tabs
        self.create_system_tab()
        self.create_browser_tab()
        self.create_events_tab()
        self.create_ioc_tab()
        self.create_report_tab()

        # Status bar
        self.create_status_bar()

        # Check OS compatibility
        self.show_os_info()

    def create_header(self):
        header_frame = ttk.Frame(self.main_container)
        header_frame.pack(fill='x', pady=(0, 10))

        title_label = ttk.Label(header_frame, text="🔍 Digital Forensic Investigation Tool",
                               font=('Arial', 20, 'bold'))
        title_label.pack(side='left')

        os_label = ttk.Label(header_frame, text=f"OS: {self.current_os}",
                            font=('Arial', 12))
        os_label.pack(side='right', padx=10)

    def create_system_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='📊 System Analysis')

        # Left panel - System Info
        left_frame = ttk.LabelFrame(tab, text="System Information", padding=10)
        left_frame.pack(side='left', fill='both', expand=True, padx=5)

        self.system_text = scrolledtext.ScrolledText(left_frame, height=20, width=50,
                                                     bg='#ecf0f1', fg='#2c3e50')
        self.system_text.pack(fill='both', expand=True, pady=5)

        # Right panel - Timeline
        right_frame = ttk.LabelFrame(tab, text="Timeline & Activity", padding=10)
        right_frame.pack(side='right', fill='both', expand=True, padx=5)

        self.timeline_text = scrolledtext.ScrolledText(right_frame, height=20, width=50,
                                                       bg='#ecf0f1', fg='#2c3e50')
        self.timeline_text.pack(fill='both', expand=True, pady=5)

        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(side='bottom', fill='x', pady=10)

        ttk.Button(btn_frame, text="Collect System Info",
                  command=self.collect_system_info).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Collect Timeline",
                  command=self.collect_timeline).pack(side='left', padx=5)

    def create_browser_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='🌐 Browser Artifacts')

        # Browser selection
        browser_frame = ttk.LabelFrame(tab, text="Browser Selection", padding=10)
        browser_frame.pack(fill='x', padx=5, pady=5)

        self.browser_vars = {}
        browsers = ['Chrome', 'Firefox', 'Safari', 'Microsoft Edge', 'Brave']

        for i, browser in enumerate(browsers):
            var = tk.BooleanVar(value=True)
            self.browser_vars[browser] = var
            ttk.Checkbutton(browser_frame, text=browser, variable=var).pack(side='left', padx=10)

        # History display
        history_frame = ttk.LabelFrame(tab, text="Browser History & Activity", padding=10)
        history_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.history_text = scrolledtext.ScrolledText(history_frame, height=15,
                                                      bg='#ecf0f1', fg='#2c3e50')
        self.history_text.pack(fill='both', expand=True)

        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Collect Browser History",
                  command=self.collect_browser_history).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear Results",
                  command=lambda: self.clear_text(self.history_text)).pack(side='left', padx=5)

    def create_events_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='📋 Event Logs')

        # Event log display
        log_frame = ttk.LabelFrame(tab, text="System Events & Logs", padding=10)
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=20,
                                                  bg='#ecf0f1', fg='#2c3e50')
        self.log_text.pack(fill='both', expand=True)

        # Control panel
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill='x', pady=10)

        ttk.Button(control_frame, text="Collect Event Logs",
                  command=self.collect_event_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Collect Network Activity",
                  command=self.collect_network_activity).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Clear Logs",
                  command=lambda: self.clear_text(self.log_text)).pack(side='left', padx=5)

    def create_ioc_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='🔐 IOC Extraction')

        # File selection
        file_frame = ttk.LabelFrame(tab, text="File Selection", padding=10)
        file_frame.pack(fill='x', padx=5, pady=5)

        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=70).pack(side='left', padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side='left', padx=5)

        # Hash display
        hash_frame = ttk.LabelFrame(tab, text="Hash Values", padding=10)
        hash_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.hash_text = scrolledtext.ScrolledText(hash_frame, height=15,
                                                   bg='#ecf0f1', fg='#2c3e50')
        self.hash_text.pack(fill='both', expand=True)

        # Verification
        verify_frame = ttk.LabelFrame(tab, text="Hash Verification", padding=10)
        verify_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(verify_frame, text="Calculate Hashes",
                  command=self.calculate_hashes).pack(side='left', padx=5)
        ttk.Button(verify_frame, text="Verify Hash",
                  command=self.verify_hash).pack(side='left', padx=5)

    def create_report_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text='📄 Report Generation')

        # Report options
        options_frame = ttk.LabelFrame(tab, text="Report Options", padding=10)
        options_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(options_frame, text="Report Format:").pack(side='left', padx=5)
        self.report_format = ttk.Combobox(options_frame, values=['PDF', 'HTML', 'JSON', 'TXT'],
                                          state='readonly')
        self.report_format.set('PDF')
        self.report_format.pack(side='left', padx=5)

        ttk.Button(options_frame, text="Generate Report",
                  command=self.generate_report).pack(side='left', padx=20)

        # Report preview
        preview_frame = ttk.LabelFrame(tab, text="Report Preview", padding=10)
        preview_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.report_text = scrolledtext.ScrolledText(preview_frame, height=20,
                                                     bg='#ecf0f1', fg='#2c3e50')
        self.report_text.pack(fill='both', expand=True)

    def create_status_bar(self):
        status_frame = ttk.Frame(self.main_container)
        status_frame.pack(fill='x', pady=(10, 0))

        self.status_label = ttk.Label(status_frame, text="Ready",
                                      font=('Arial', 10))
        self.status_label.pack(side='left')

        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress_bar.pack(side='right', padx=10)

    def show_os_info(self):
        info = f"Operating System: {self.current_os}\n"
        info += f"Platform: {platform.platform()}\n"
        info += f"Processor: {platform.processor()}\n"
        info += f"Python Version: {sys.version}\n"
        info += "-" * 50 + "\n"
        info += "This tool can collect forensic artifacts from:\n"
        info += "✓ System Information\n"
        info += "✓ Browser History (Chrome, Firefox, Safari, Edge, Brave)\n"
        info += "✓ Event Logs\n"
        info += "✓ Network Activity\n"
        info += "✓ File Hashes (MD5, SHA1, SHA256, SHA512)\n"
        info += "✓ Timeline Analysis\n"

        self.system_text.insert('1.0', info)

    def collect_system_info(self):
        """Collect system information"""
        self.status_label.config(text="Collecting system information...")
        self.progress_bar.start()

        try:
            info = "=" * 60 + "\n"
            info += f"SYSTEM INFORMATION\n"
            info += f"Collected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            info += "=" * 60 + "\n\n"

            info += f"Operating System: {self.current_os}\n"
            info += f"Platform: {platform.platform()}\n"
            info += f"Processor: {platform.processor()}\n"
            info += f"Architecture: {platform.machine()}\n"
            info += f"Hostname: {platform.node()}\n\n"

            # OS specific info
            if self.current_os == "Windows":
                info += self.collect_windows_system_info()
            elif self.current_os == "Linux":
                info += self.collect_linux_system_info()
            elif self.current_os == "Darwin":  # macOS
                info += self.collect_macos_system_info()

            self.system_text.insert('end', info)
            self.system_text.see('end')

            self.investigation_data['system_info'] = info

        except Exception as e:
            self.system_text.insert('end', f"Error collecting system info: {str(e)}\n")

        self.status_label.config(text="System information collected")
        self.progress_bar.stop()

    def collect_windows_system_info(self):
        info = ""
        try:
            # System info
            result = subprocess.run(['systeminfo'], capture_output=True, text=True)
            info += "System Details:\n"
            info += result.stdout[:500] + "...\n\n"

            # Running processes
            result = subprocess.run(['tasklist'], capture_output=True, text=True)
            info += "Running Processes:\n"
            info += result.stdout[:500] + "...\n"
        except:
            pass
        return info

    def collect_linux_system_info(self):
        info = ""
        try:
            # CPU info
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read()[:500]
            info += f"CPU Info:\n{cpu_info}...\n\n"

            # Memory info
            with open('/proc/meminfo', 'r') as f:
                mem_info = f.read()[:300]
            info += f"Memory Info:\n{mem_info}...\n\n"
        except:
            pass
        return info

    def collect_macos_system_info(self):
        info = ""
        try:
            # System version
            result = subprocess.run(['sw_vers'], capture_output=True, text=True)
            info += f"macOS Version:\n{result.stdout}\n\n"

            # System profiler
            result = subprocess.run(['system_profiler', 'SPHardwareDataType'],
                                   capture_output=True, text=True)
            info += f"Hardware Info:\n{result.stdout[:500]}...\n"
        except:
            pass
        return info

    def chrome_timestamp_to_datetime(self, timestamp):
        """Convert Chromium/WebKit timestamp to readable datetime"""
        try:
            from datetime import datetime, timedelta

            return (
                datetime(1601, 1, 1) +
                timedelta(microseconds=timestamp)
            ).strftime("%Y-%m-%d %H:%M:%S")

        except Exception:
            return "Unknown"

    def collect_timeline(self):
        """Collect complete system timeline (all files, recursively) for all OS"""
        self.status_label.config(text="Collecting timeline (this may take a while)...")
        self.progress_bar.start()

        try:
            timeline = "=" * 60 + "\n"
            timeline += f"SYSTEM TIMELINE (COMPLETE)\n"
            timeline += f"Collected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            timeline += "=" * 60 + "\n\n"
            timeline += "All Files (Created/Modified/Accessed Timeline):\n"
            timeline += "-" * 40 + "\n"

            # Check common directories
            if self.current_os == "Windows":
                paths = [
                    os.path.expanduser("~\\Documents"),
                    os.path.expanduser("~\\Downloads"),
                    os.path.expanduser("~\\Desktop"),
                    os.path.expanduser("~\\Pictures"),
                    os.path.expanduser("~\\AppData\\Local\\Temp")
                ]
            else:
                paths = [
                    os.path.expanduser("~/Documents"),
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    os.path.expanduser("~/Pictures"),
                    "/tmp"
                ]

            for path in paths:
               if os.path.exists(path):
                    timeline += f"\nDirectory: {path}\n"
                    
                    for root_dir, dirs, files in os.walk(path):
                        
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        
                        for file in files:
                            file_path = os.path.join(root_dir, file)
                            try:
                                if os.path.isfile(file_path):
                                    stat = os.stat(file_path)
                                    
                                    mtime = datetime.fromtimestamp(stat.st_mtime)
                                    ctime = datetime.fromtimestamp(stat.st_ctime)

                                    try:
                                        atime = datetime.fromtimestamp(stat.st_atime)
                                    except Exception:
                                        atime = None
                                        
                                    rel = os.path.relpath(file_path, path)
                                    
                                    timeline += (
                                        f"{rel} | "
                                        f"Modified: {mtime.strftime('%Y-%m-%d %H:%M:%S')} | "
                                        f"Created: {ctime.strftime('%Y-%m-%d %H:%M:%S')}"
                                    )
                                     
                                    if atime:
                                        timeline += f" | Accessed: {atime.strftime('%Y-%m-%d %H:%M:%S')}"

                                    timeline += "\n"
                                    
                            except (PermissionError, FileNotFoundError, OSError):
                                continue
   
            self.timeline_text.delete("1.0", "end")
            self.timeline_text.insert("1.0", timeline)
            self.timeline_text.see("1.0")

            self.investigation_data["timeline"] = timeline

        except Exception as e:
            self.timeline_text.insert("1.0", f"Error collecting timeline: {e}")

        self.status_label.config(text="Timeline collected (complete)")
        self.progress_bar.stop()
        
        
    def collect_browser_history(self):
        """Collect browser history from selected browsers"""
        self.status_label.config(text="Collecting browser history...")
        self.progress_bar.start()

        self.history_text.delete('1.0', 'end')

        try:
            history = "=" * 60 + "\n"
            history += f"BROWSER HISTORY & ACTIVITY\n"
            history += f"Collected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            history += "=" * 60 + "\n\n"

            collected_any = False

            # Chrome
            if self.browser_vars['Chrome'].get():
                chrome_history = self.collect_chrome_history()
                if chrome_history:
                    history += "CHROME HISTORY:\n" + "-" * 40 + "\n" + chrome_history + "\n"
                    collected_any = True

            # Firefox
            if self.browser_vars['Firefox'].get():
                firefox_history = self.collect_firefox_history()
                if firefox_history:
                    history += "FIREFOX HISTORY:\n" + "-" * 40 + "\n" + firefox_history + "\n"
                    collected_any = True

            # Edge
            if self.browser_vars['Microsoft Edge'].get():
                edge_history = self.collect_edge_history()
                if edge_history:
                    history += "EDGE HISTORY:\n" + "-" * 40 + "\n" + edge_history + "\n"
                    collected_any = True

            # Brave
            if self.browser_vars['Brave'].get():
                brave_history = self.collect_brave_history()
                if brave_history:
                    history += "BRAVE HISTORY:\n" + "-" * 40 + "\n" + brave_history + "\n"
                    collected_any = True

            # Safari (macOS only)
            if self.browser_vars['Safari'].get() and self.current_os == "Darwin":
                safari_history = self.collect_safari_history()
                if safari_history:
                    history += "SAFARI HISTORY:\n" + "-" * 40 + "\n" + safari_history + "\n"
                    collected_any = True

            if not collected_any:
                history += "No browser history found or browsers not installed.\n"
                history += "Note: Some browsers may require administrative privileges.\n"

            self.history_text.insert('1.0', history)
            self.investigation_data['browser_history'] = history

        except Exception as e:
            self.history_text.insert('1.0', f"Error collecting browser history: {str(e)}\n")

        self.status_label.config(text="Browser history collected")
        self.progress_bar.stop()

    def collect_chrome_history(self):
        """Collect Chrome browser history"""
        history_data = ""
        try:
            if self.current_os == "Windows":
                chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")
            elif self.current_os == "Linux":
                chrome_path = os.path.expanduser("~/.config/google-chrome/Default/History")
            elif self.current_os == "Darwin":
                chrome_path = os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/History")
            else:
                return ""

            if os.path.exists(chrome_path):
                # Copy to temp to avoid lock issues
                temp_path = "temp_chrome_history.db"
                shutil.copy2(chrome_path, temp_path)

                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT urls.url, urls.title, visits.visit_time, visits.from_visit, visits.transition FROM visits JOIN urls ON visits.url = urls.id ORDER BY visits.visit_time DESC")
                rows = cursor.fetchall()
                conn.close()
                os.remove(temp_path)

                for row in rows:
                    url, title, visit_time, from_visit, transition = row
                    if title:
                        history_data += f"URL: {url}\n"
                        history_data += f"Title: {title}\n"
                        history_data += f"Visit Time: {self.chrome_timestamp_to_datetime(visit_time)}\n"
                        history_data += f"From Visit ID: {from_visit}\n"
                        history_data += f"Transition: {transition}\n"
                        history_data += "-" * 60 + "\n"
            else:
                history_data = "Chrome history not found.\n"
        except Exception as e:
            history_data = f"Error reading Chrome history: {str(e)}\n"

        return history_data

    def collect_firefox_history(self):
        """Collect Firefox browser history"""
        history_data = ""
        try:
            if self.current_os == "Windows":
                firefox_path = os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
            elif self.current_os == "Linux":
                firefox_path = os.path.expanduser("~/.mozilla/firefox")
            elif self.current_os == "Darwin":
                firefox_path = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
            else:
                return ""

            if os.path.exists(firefox_path):
                # Find the first profile
                profiles = []

                for d in os.listdir(firefox_path):
                    db = os.path.join(firefox_path, d, "places.sqlite")
                    if os.path.exists(db):
                        profiles.append(d)
                # profiles = [d for d in os.listdir(firefox_path) if d.endswith('.default') or d.endswith('.default-release')]
                if profiles:
                    profile_path = os.path.join(firefox_path, profiles[0], 'places.sqlite')
                    if os.path.exists(profile_path):
                        temp_path = "temp_firefox_history.db"
                        shutil.copy2(profile_path, temp_path)

                        conn = sqlite3.connect(temp_path)
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT url, title, last_visit_date
                            FROM moz_places
                            ORDER BY last_visit_date DESC
                        """)
                        rows = cursor.fetchall()
                        conn.close()
                        os.remove(temp_path)

                        for row in rows:
                            url, title, timestamp = row
                            visit_time = "Unknown"

                            if timestamp:
                                try:
                                    visit_time = datetime.fromtimestamp(
                                        timestamp / 1000000
                                    ).strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    pass

                            history_data += f"URL: {url}\n"
                            history_data += f"Title: {title}\n"
                            history_data += f"Last Visit: {visit_time}\n"
                            history_data += "-" * 60 + "\n"
                    else:
                        history_data = "Firefox places.sqlite not found.\n"
                else:
                    history_data = "Firefox profile not found.\n"
            else:
                history_data = "Firefox path not found.\n"
        except Exception as e:
            history_data = f"Error reading Firefox history: {str(e)}\n"

        return history_data

    def collect_edge_history(self):
        """Collect Microsoft Edge browser history"""
        history_data = ""
        try:
            if self.current_os == "Windows":
                edge_path = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History")
            elif self.current_os == "Linux":
                edge_path = os.path.expanduser("~/.config/microsoft-edge/Default/History")
            elif self.current_os == "Darwin":
                edge_path = os.path.expanduser("~/Library/Application Support/Microsoft Edge/Default/History")
            else:
                return ""

            if os.path.exists(edge_path):
                temp_path = "temp_edge_history.db"
                shutil.copy2(edge_path, temp_path)

                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT urls.url, urls.title, visits.visit_time, visits.from_visit, visits.transition FROM visits JOIN urls ON visits.url = urls.id ORDER BY visits.visit_time DESC")
                rows = cursor.fetchall()
                conn.close()
                os.remove(temp_path)

                for row in rows:
                    url, title, visit_time, from_visit, transition = row
                    if title:
                        history_data += f"URL: {url}\n"
                        history_data += f"Title: {title}\n"
                        history_data += f"Visit Time: {self.chrome_timestamp_to_datetime(visit_time)}\n"
                        history_data += f"From Visit ID: {from_visit}\n"
                        history_data += f"Transition: {transition}\n"
                        history_data += "-" * 60 + "\n"
            else:
                history_data = "Edge history not found.\n"
        except Exception as e:
            history_data = f"Error reading Edge history: {str(e)}\n"

        return history_data

    def collect_brave_history(self):
        """Collect Brave browser history"""
        history_data = ""
        try:
            if self.current_os == "Windows":
                brave_path = os.path.expanduser("~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History")
            elif self.current_os == "Linux":
                brave_path = os.path.expanduser("~/.config/BraveSoftware/Brave-Browser/Default/History")
            elif self.current_os == "Darwin":
                brave_path = os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser/Default/History")
            else:
                return ""

            if os.path.exists(brave_path):
                temp_path = "temp_brave_history.db"
                shutil.copy2(brave_path, temp_path)

                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT urls.url, urls.title, visits.visit_time, visits.from_visit, visits.transition FROM visits JOIN urls ON visits.url = urls.id ORDER BY visits.visit_time DESC")
                rows = cursor.fetchall()
                conn.close()
                os.remove(temp_path)

                for row in rows:
                    url, title, visit_time, from_visit, transition = row
                    if title:
                        history_data += f"URL: {url}\n"
                        history_data += f"Title: {title}\n"
                        history_data += f"Visit Time: {self.chrome_timestamp_to_datetime(visit_time)}\n"
                        history_data += f"From Visit ID: {from_visit}\n"
                        history_data += f"Transition: {transition}\n"
                        history_data += "-" * 60 + "\n"
            else:
                history_data = "Brave history not found.\n"
        except Exception as e:
            history_data = f"Error reading Brave history: {str(e)}\n"

        return history_data

    def collect_safari_history(self):
        """Collect Safari browser history (macOS only)"""
        history_data = ""
        try:
            if self.current_os == "Darwin":
                safari_path = os.path.expanduser("~/Library/Safari/History.db")
                if os.path.exists(safari_path):
                    temp_path = "temp_safari_history.db"
                    shutil.copy2(safari_path, temp_path)

                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT history_items.url, history_items.title, history_visits.visit_time FROM history_visits JOIN history_items ON history_visits.history_item = history_items.id ORDER BY history_visits.visit_time DESC;
                    """)
                    rows = cursor.fetchall()
                    conn.close()
                    os.remove(temp_path)

                    for row in rows:
                        url, title, timestamp = row
                        visit_time = "Unknown"

                        if timestamp:
                            try:
                                visit_time = datetime(2001,1,1) + timedelta(seconds=timestamp)
                                visit_time = visit_time.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                pass

                        history_data += f"URL: {url}\n"
                        history_data += f"Title: {title}\n"
                        history_data += f"Last Visit: {visit_time}\n"
                        history_data += "-" * 60 + "\n"
                else:
                    history_data = "Safari history not found.\n"
            else:
                history_data = "Safari is only available on macOS.\n"
        except Exception as e:
            history_data = f"Error reading Safari history: {str(e)}\n"

        return history_data

    def collect_event_logs(self):
        """Collect complete system event logs (no time/count limits)"""
        self.status_label.config(text="Collecting complete event logs (this may take a while)...")
        self.progress_bar.start()
        self.log_text.delete('1.0', 'end')

        try:
            logs = "=" * 60 + "\n"
            logs += f"SYSTEM EVENT LOGS (COMPLETE)\n"
            logs += f"Collected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            logs += "=" * 60 + "\n\n"

            if self.current_os == "Windows":
                logs += "Windows Event Logs:\n" + "-" * 40 + "\n"
                try:
                    result = subprocess.run(['wevtutil', 'qe', 'System', '/f:text'],
                                             capture_output=True, text=True, timeout=300)
                    logs += "System Log (Complete):\n" + result.stdout + "\n\n"
                except Exception as e:
                    logs += f"Unable to read System log: {e}. Run as administrator.\n\n"
                try:
                    result = subprocess.run(['wevtutil', 'qe', 'Application', '/f:text'],
                                             capture_output=True, text=True, timeout=300)
                    logs += "Application Log (Complete):\n" + result.stdout + "\n\n"
                except Exception as e:
                    logs += f"Unable to read Application log: {e}. Run as administrator.\n\n"

            elif self.current_os == "Linux":
                logs += "Linux System Logs:\n" + "-" * 40 + "\n"
                if os.path.exists('/var/log/syslog'):
                    with open('/var/log/syslog', 'r', errors='ignore') as f:
                        logs += "Syslog (Complete):\n" + f.read() + "\n"
                if os.path.exists('/var/log/auth.log'):
                    with open('/var/log/auth.log', 'r', errors='ignore') as f:
                        logs += "\nAuthentication Log (Complete):\n" + f.read() + "\n"

            elif self.current_os == "Darwin":
                logs += "macOS System Logs:\n" + "-" * 40 + "\n"
                try:
                    # macOS unified log retains a limited window regardless of --start,
                    # so this pulls everything still on disk.
                    result = subprocess.run(
                        ['log', 'show', '--start', '2000-01-01 00:00:00',
                         '--predicate', 'processImagePath contains "system"'],
                        capture_output=True, text=True, timeout=180)
                    logs += "System Log (Complete available history):\n" + result.stdout + "\n\n"
                except Exception as e:
                    logs += f"Unable to read system log: {e}\n\n"

            self.log_text.insert('1.0', logs)
            self.investigation_data['event_logs'] = logs

        except Exception as e:
            self.log_text.insert('1.0', f"Error collecting event logs: {str(e)}\n")

        self.status_label.config(text="Event logs collected (complete)")
        self.progress_bar.stop()

    def collect_network_activity(self):
        """Collect complete network activity information"""
        self.status_label.config(text="Collecting complete network activity...")
        self.progress_bar.start()

        try:
            network = "\n" + "=" * 60 + "\n"
            network += f"NETWORK ACTIVITY (COMPLETE)\n"
            network += f"Collected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            network += "=" * 60 + "\n\n"
            network += "Network Connections:\n" + "-" * 40 + "\n"

            if self.current_os == "Windows":
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            elif self.current_os == "Linux":
                result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
            elif self.current_os == "Darwin":
                result = subprocess.run(['netstat', '-anv'], capture_output=True, text=True)

            network += "\nActive Connections (Detailed):\n" + "-" * 40 + "\n"
            try:
                if self.current_os == "Windows":
                    result = subprocess.run(['netstat', '-b'], capture_output=True, text=True, timeout=30)
                elif self.current_os == "Linux":
                    result = subprocess.run(['netstat', '-tunp'], capture_output=True, text=True, timeout=30)
                elif self.current_os == "Darwin":
                    result = subprocess.run(['lsof', '-i'], capture_output=True, text=True)
                network += result.stdout + "\n"
            except Exception as e:
                network += f"Unable to get detailed connection info: {e}\n"

            self.log_text.insert('end', network)
            self.log_text.see('end')
            self.investigation_data['network_activity'] = network

        except Exception as e:
            self.log_text.insert('end', f"Error collecting network activity: {str(e)}\n")

        self.status_label.config(text="Network activity collected (complete)")
        self.progress_bar.stop()

    def browse_file(self):
        """Browse for a file to analyze"""
        filename = filedialog.askopenfilename(title="Select File for Hash Analysis")
        if filename:
            self.file_path.set(filename)

    def calculate_hashes(self):
        """Calculate hashes of selected file"""
        file_path = self.file_path.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file.")
            return

        self.status_label.config(text="Calculating hashes...")
        self.progress_bar.start()

        try:
            self.hash_text.delete('1.0', 'end')

            hashes = "=" * 60 + "\n"
            hashes += f"HASH VALUES\n"
            hashes += f"File: {file_path}\n"
            hashes += f"Calculated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            hashes += "=" * 60 + "\n\n"

            # Calculate hashes
            with open(file_path, 'rb') as f:
                data = f.read()

                md5_hash = hashlib.md5(data).hexdigest()
                sha1_hash = hashlib.sha1(data).hexdigest()
                sha256_hash = hashlib.sha256(data).hexdigest()
                sha512_hash = hashlib.sha512(data).hexdigest()

                hashes += f"MD5:    {md5_hash}\n"
                hashes += f"SHA1:   {sha1_hash}\n"
                hashes += f"SHA256: {sha256_hash}\n"
                hashes += f"SHA512: {sha512_hash}\n"

                # Store for verification
                self.investigation_data['file_hashes'] = {
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash,
                    'sha512': sha512_hash
                }

            self.hash_text.insert('1.0', hashes)

        except Exception as e:
            self.hash_text.insert('1.0', f"Error calculating hashes: {str(e)}\n")

        self.status_label.config(text="Hashes calculated")
        self.progress_bar.stop()

    def verify_hash(self):
        """Verify a hash against the calculated ones"""
        if not hasattr(self, 'investigation_data') or 'file_hashes' not in self.investigation_data:
            messagebox.showerror("Error", "Please calculate hashes first.")
            return

        # Create verification dialog
        verify_window = tk.Toplevel(self.root)
        verify_window.title("Hash Verification")
        verify_window.geometry("500x300")
        verify_window.configure(bg='#2c3e50')

        ttk.Label(verify_window, text="Enter Hash to Verify:",
                 font=('Arial', 12)).pack(pady=10)

        hash_entry = ttk.Entry(verify_window, width=60)
        hash_entry.pack(pady=10)

        result_label = ttk.Label(verify_window, text="", font=('Arial', 11))
        result_label.pack(pady=20)

        def verify():
            entered_hash = hash_entry.get().strip().lower()
            if not entered_hash:
                result_label.config(text="Please enter a hash value.", foreground='red')
                return

            # Check against all calculated hashes
            found = False
            for hash_type, hash_value in self.investigation_data['file_hashes'].items():
                if entered_hash == hash_value:
                    result_label.config(text=f"✓ Hash matches {hash_type.upper()}!", foreground='green')
                    found = True
                    break

            if not found:
                result_label.config(text="✗ Hash does not match any calculated hash.", foreground='red')

        ttk.Button(verify_window, text="Verify", command=verify).pack(pady=10)
        ttk.Button(verify_window, text="Close", command=verify_window.destroy).pack(pady=5)

    def generate_report(self):
        """Generate investigation report"""
        self.status_label.config(text="Generating report...")
        self.progress_bar.start()

        report_format = self.report_format.get()

        try:
            # Prepare report content
            report = "=" * 70 + "\n"
            report += "DIGITAL FORENSIC INVESTIGATION REPORT\n"
            report += "=" * 70 + "\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += f"Operating System: {self.current_os}\n"
            report += "=" * 70 + "\n\n"

            # Add collected data
            if 'system_info' in self.investigation_data:
                report += "SYSTEM INFORMATION\n"
                report += "-" * 40 + "\n"
                report += self.investigation_data['system_info'] + "\n"

            if 'browser_history' in self.investigation_data:
                report += "BROWSER HISTORY\n"
                report += "-" * 40 + "\n"
                report += self.investigation_data['browser_history'] + "\n"

            if 'event_logs' in self.investigation_data:
                report += "EVENT LOGS\n"
                report += "-" * 40 + "\n"
                report += self.investigation_data['event_logs'] + "\n"

            if 'network_activity' in self.investigation_data:
                report += "NETWORK ACTIVITY\n"
                report += "-" * 40 + "\n"
                report += self.investigation_data['network_activity'] + "\n"

            if 'file_hashes' in self.investigation_data:
                report += "FILE HASHES\n"
                report += "-" * 40 + "\n"
                for hash_type, hash_value in self.investigation_data['file_hashes'].items():
                    report += f"{hash_type.upper()}: {hash_value}\n"

            # Update preview
            self.report_text.delete('1.0', 'end')
            self.report_text.insert('1.0', report)

            # Save report
            if report_format == 'PDF':
                self.save_pdf_report(report)
            elif report_format == 'HTML':
                self.save_html_report(report)
            elif report_format == 'JSON':
                self.save_json_report()
            else:  # TXT
                self.save_txt_report(report)

        except Exception as e:
            messagebox.showerror("Error", f"Error generating report: {str(e)}")

        self.status_label.config(text="Report generated")
        self.progress_bar.stop()

    def save_txt_report(self, report):
        """Save report as TXT"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(report)
            messagebox.showinfo("Success", f"Report saved to {filename}")

    def save_html_report(self, report):
        """Save report as HTML"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        if filename:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Digital Forensic Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
                    .section {{ margin: 20px 0; padding: 10px; background: #f8f9fa; border-radius: 5px; }}
                    .hash {{ font-family: monospace; }}
                </style>
            </head>
            <body>
                <h1>Digital Forensic Investigation Report</h1>
                <div class="section">
                    <pre>{report}</pre>
                </div>
            </body>
            </html>
            """
            with open(filename, 'w') as f:
                f.write(html_content)
            messagebox.showinfo("Success", f"Report saved to {filename}")

    def save_json_report(self):
        """Save report as JSON"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if filename:
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'os': self.current_os,
                'data': self.investigation_data
            }
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            messagebox.showinfo("Success", f"Report saved to {filename}")

    def save_pdf_report(self, report):
        """Save report as PDF (requires reportlab)"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            if filename:
                doc = SimpleDocTemplate(filename, pagesize=letter)
                styles = getSampleStyleSheet()
                story = []

                # Add content
                for line in report.split('\n'):
                    if line.strip():
                        if '=' in line and len(line) > 20:
                            story.append(Paragraph(line, styles['Heading2']))
                        elif '-' in line and len(line) > 20:
                            story.append(Paragraph(line, styles['Heading3']))
                        else:
                            story.append(Paragraph(line, styles['Normal']))
                        story.append(Spacer(1, 6))

                doc.build(story)
                messagebox.showinfo("Success", f"Report saved to {filename}")

        except ImportError:
            messagebox.showwarning("Warning",
                "ReportLab not installed. PDF reports require: pip install reportlab")
            self.save_txt_report(report)

    def clear_text(self, text_widget):
        """Clear a text widget"""
        text_widget.delete('1.0', 'end')

    def clear_all_data(self):
        """Clear all investigation data"""
        if messagebox.askyesno("Confirm", "Clear all collected data?"):
            self.investigation_data = {}
            self.system_text.delete('1.0', 'end')
            self.timeline_text.delete('1.0', 'end')
            self.history_text.delete('1.0', 'end')
            self.log_text.delete('1.0', 'end')
            self.hash_text.delete('1.0', 'end')
            self.report_text.delete('1.0', 'end')
            self.file_path.set("")

            # Show welcome message again
            self.show_os_info()

def main():
    # Check for required packages
    try:
        import tkinter
    except ImportError:
        print("Tkinter is required but not installed.")
        print("Install it using:")
        print("  - Ubuntu/Debian: sudo apt-get install python3-tk")
        print("  - Fedora: sudo dnf install python3-tkinter")
        print("  - macOS: brew install python-tk")
        print("  - Windows: Included with Python installation")
        sys.exit(1)

    root = tk.Tk()
    app = DigitalForensicTool(root)

    # Add cleanup menu
    menubar = tk.Menu(root)
    file_menu = tk.Menu(menubar, tearoff=0)
    file_menu.add_command(label="Clear All Data", command=app.clear_all_data)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    menubar.add_cascade(label="File", menu=file_menu)
    root.config(menu=menubar)

    root.mainloop()

if __name__ == "__main__":
    main()

