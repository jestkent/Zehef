import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import asyncio
import sys
import io
import platform
import re
import requests

# Import the main function from your app
from main import main as zehef_main
from lib.helpers import show_banner

def geolocate_ips_in_output(output):
    ip_regex = r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
    ips = set(re.findall(ip_regex, output))
    geo_results = []
    for ip in ips:
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = resp.json()
            if data.get("status") == "success":
                geo = f"IP {ip}: {data.get('country', '?')}, {data.get('regionName', '?')}, {data.get('city', '?')} (Lat: {data.get('lat', '?')}, Lon: {data.get('lon', '?')})"
            else:
                geo = f"IP {ip}: Location not found"
        except Exception as e:
            geo = f"IP {ip}: Error during geolocation ({e})"
        geo_results.append(geo)
    if geo_results:
        return "\n--- Geolocation Results ---\n" + "\n".join(geo_results) + "\n"
    return ""

def run_zehef_async(email, output_widget):
    def thread_runner():
        print("[DEBUG] Thread started")
        if platform.system() == "Windows":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        async def runner():
            old_stdout = sys.stdout
            try:
                show_banner()
                sys.stdout = mystdout = io.StringIO()
                await zehef_main(email)
                output = mystdout.getvalue()
                geo_info = geolocate_ips_in_output(output)
                def update_output():
                    explanation = (
                        "Zehef OSINT Email Tracker\n"
                        "--------------------------\n"
                        "This tool gathers public information about the email you entered, including breaches, leaks, and accounts found on various services.\n"
                        "Below are the results of the investigation.\n\n"
                        "--- OSINT Results ---\n"
                    )
                    output_widget.insert(tk.END, explanation)
                    output_widget.insert(tk.END, output)
                    if geo_info:
                        geo_expl = (
                            "\n--- Geolocation Explanation ---\n"
                            "If any IP addresses were found in breach data, their approximate physical locations are shown below. "
                            "This is based on public IP geolocation and may not be exact.\n"
                        )
                        output_widget.insert(tk.END, geo_expl)
                        output_widget.insert(tk.END, geo_info)
                    output_widget.insert(tk.END, "\nDone!\n")
                output_widget.after(0, update_output)
            except Exception as e:
                def show_error():
                    output_widget.insert(tk.END, f"\nError: {e}\n")
                    messagebox.showerror("Error", str(e))
                output_widget.after(0, show_error)
            finally:
                sys.stdout = old_stdout
        try:
            asyncio.run(runner())
        except Exception as e:
            print(f"[DEBUG] Fatal error in thread: {e}")
    threading.Thread(target=thread_runner).start()

def start_zehef(email_entry, output_widget):
    email = email_entry.get().strip()
    output_widget.delete(1.0, tk.END)
    if not email:
        output_widget.insert(tk.END, "Please enter an email address.\n")
        return
    run_zehef_async(email, output_widget)

def main():
    root = tk.Tk()
    root.title("Zehef GUI")
    root.geometry("700x500")

    label = tk.Label(root, text="Zehef Tracker", font=("Arial", 18, "bold"))
    label.pack(pady=10)

    email_frame = tk.Frame(root)
    email_frame.pack(pady=5)
    email_label = tk.Label(email_frame, text="Email to track:", font=("Arial", 12))
    email_label.pack(side=tk.LEFT, padx=5)
    email_entry = tk.Entry(email_frame, font=("Arial", 12), width=40)
    email_entry.pack(side=tk.LEFT, padx=5)

    output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20, font=("Consolas", 10))
    output.pack(padx=10, pady=10)

    run_button = tk.Button(root, text="Track Email", command=lambda: start_zehef(email_entry, output), font=("Arial", 12), bg="#4CAF50", fg="white")
    run_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
