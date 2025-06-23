import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import socket
import datetime
import struct

logs = []

root = tk.Tk()
root.title("Raw Modbus TCP Sender (with Malicious Options)")
root.geometry("950x800")

# IP and Port
ip_entry = tk.Entry(root, width=30)
ip_entry.insert(0, "127.0.0.1")
port_entry = tk.Entry(root, width=10)
port_entry.insert(0, "502")

tk.Label(root, text="Modbus Server IP:").pack(anchor='w')
ip_entry.pack(anchor='w')
tk.Label(root, text="Port:").pack(anchor='w')
port_entry.pack(anchor='w')

status_label = tk.Label(root, text="🔴 Not Connected", fg="red")
status_label.pack()

def test_connection():
    ip = ip_entry.get()
    port = int(port_entry.get())
    try:
        s = socket.create_connection((ip, port), timeout=2)
        s.close()
        status_label.config(text="🟢 Connected", fg="green")
        log_msg = f"[{datetime.datetime.now()}] Connection to {ip}:{port} successful.\n"
    except Exception as e:
        status_label.config(text="🔴 Connection Failed", fg="red")
        log_msg = f"[{datetime.datetime.now()}] Connection to {ip}:{port} failed: {e}\n"
    output_text.insert(tk.END, log_msg)
    logs.append(log_msg)

tk.Button(root, text="Connect", command=test_connection).pack(pady=5)

# --- Malicious Crafting Options ---
malicious_frame = tk.LabelFrame(root, text="Malicious Packet Crafting Options")
malicious_frame.pack(fill="x", padx=10, pady=5)
malicious_options = {
    "invalid_function": tk.BooleanVar(),
    "out_of_range_address": tk.BooleanVar(),
    "incorrect_length": tk.BooleanVar(),
    "extra_bytes": tk.BooleanVar(),
    "corrupted_header": tk.BooleanVar()
}
tk.Checkbutton(malicious_frame, text="Invalid Function Code", variable=malicious_options["invalid_function"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Out-of-Range Address", variable=malicious_options["out_of_range_address"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Incorrect Length Field", variable=malicious_options["incorrect_length"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Extra Bytes in Payload", variable=malicious_options["extra_bytes"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Corrupted MBAP Header", variable=malicious_options["corrupted_header"]).pack(anchor='w')

# --- Predefined Malicious Packet Dropdown ---
def fill_predef_packet(event=None):
    val = mal_predef.get()
    preset = ""
    if val == "Invalid Function Code packet":
        preset = "000100000006019900000001"
    elif val == "Out-of-range coil read":
        preset = "0001000000060101FFFF0001"
    elif val == "Incomplete PDU with fake length":
        preset = "00010000001001030000"
    elif val == "Malformed multi-coil write":
        preset = "000100000009010F00000102"
    elif val == "Valid packet with trailing junk":
        preset = "000100000006010300000001DEADBEEF"
    hex_entry.delete(0, tk.END)
    hex_entry.insert(0, preset)

mal_predef = ttk.Combobox(malicious_frame, values=[
    "Invalid Function Code packet",
    "Out-of-range coil read",
    "Incomplete PDU with fake length",
    "Malformed multi-coil write",
    "Valid packet with trailing junk"
], state="readonly", width=35)
mal_predef.pack(anchor="w", padx=10, pady=3)
mal_predef.bind("<<ComboboxSelected>>", fill_predef_packet)

# --- Manual Hex Packet Input ---
tk.Label(root, text="Enter Full Hex Packet:").pack(anchor='w')
hex_entry = tk.Entry(root, width=100)
hex_entry.pack(anchor='w', padx=10, pady=5)

# --- Subfield Controls ---
subfield_toggle_var = tk.BooleanVar()
subfield_toggle = tk.Checkbutton(root, text="Use Subfield Inputs", variable=subfield_toggle_var)
subfield_toggle.pack(anchor='w', padx=10)

subfield_frame = tk.Frame(root)
subfield_frame.pack(anchor='w', padx=10)
subfield_entries = []
subfield_labels = ["Transaction ID", "Protocol ID", "Length", "Unit ID", "Function Code", "Data"]

for i, label in enumerate(subfield_labels):
    tk.Label(subfield_frame, text=label).grid(row=0, column=i, padx=2)
    if label == "Function Code":
        fcode_var = tk.StringVar()
        fcode_dropdown = ttk.Combobox(subfield_frame, textvariable=fcode_var, width=15)
        fcode_dropdown['values'] = [
            "01 Read Coils", "02 Read Discrete Inputs", "03 Read Holding Registers",
            "04 Read Input Registers", "05 Write Single Coil", "06 Write Single Register",
            "0F Write Multiple Coils", "10 Write Multiple Registers",
            "11 Report Slave ID", "17 Read/Write Multiple Registers"
        ]
        fcode_dropdown.set("01 Read Coils")
        fcode_dropdown.bind("<<ComboboxSelected>>", lambda e: autofill_data())
        fcode_dropdown.grid(row=1, column=i, padx=2)
        subfield_entries.append(fcode_dropdown)
    elif label == "Data":
        data_frame = tk.Frame(subfield_frame)
        data_frame.grid(row=1, column=i, padx=2)
        sub_data_entries = []
        sub_data_labels = ["Start Addr", "Quantity/Value", "Byte Count", "Payload"]
        for j in range(4):
            tk.Label(data_frame, text=sub_data_labels[j]).grid(row=0, column=j, padx=1)
            entry = tk.Entry(data_frame, width=6)
            entry.grid(row=1, column=j, padx=1)
            sub_data_entries.append(entry)
        subfield_entries.append(data_frame)
    else:
        entry = tk.Entry(subfield_frame, width=10)
        entry.grid(row=1, column=i, padx=2)
        subfield_entries.append(entry)

def autofill_data():
    selected_code = fcode_var.get().split()[0]
    default_values = {
        "01": ["0001", "0000", "0006", "01", "01", ["0000", "0001", "", ""]],
        "02": ["0001", "0000", "0006", "01", "02", ["0000", "0001", "", ""]],
        "03": ["0001", "0000", "0006", "01", "03", ["0000", "0001", "", ""]],
        "04": ["0001", "0000", "0006", "01", "04", ["0000", "0001", "", ""]],
        "05": ["0001", "0000", "0006", "01", "05", ["0001", "FF00", "", ""]],
        "06": ["0001", "0000", "0006", "01", "06", ["0001", "000A", "", ""]],
        "0F": ["0001", "0000", "0008", "01", "0F", ["0000", "0001", "01", "FF"]],
        "10": ["0001", "0000", "0009", "01", "10", ["0000", "0001", "02", "000A"]],
        "11": ["0001", "0000", "0002", "01", "11", ["", "", "", ""]],
        "17": ["0001", "0000", "000B", "01", "17", ["0000", "0001", "0000", "0002"]],
    }
    if selected_code in default_values:
        tid, pid, length, uid, fcode, data_parts = default_values[selected_code]
        subfield_entries[0].delete(0, tk.END)
        subfield_entries[0].insert(0, tid)
        subfield_entries[1].delete(0, tk.END)
        subfield_entries[1].insert(0, pid)
        subfield_entries[2].delete(0, tk.END)
        subfield_entries[2].insert(0, length)
        subfield_entries[3].delete(0, tk.END)
        subfield_entries[3].insert(0, uid)
        fcode_var.set(selected_code)
        for i in range(4):
            sub_data_entries[i].delete(0, tk.END)
            sub_data_entries[i].insert(0, data_parts[i])

def send_raw_packet():
    ip = ip_entry.get()
    port = int(port_entry.get())
    use_subfields = subfield_toggle_var.get()
    if use_subfields:
        hex_parts = []
        for i, entry in enumerate(subfield_entries):
            if i == 4:
                val = fcode_var.get().split()[0]
            elif i == 5:
                val = "".join(e.get().strip() for e in sub_data_entries)
            else:
                val = entry.get().strip()
            if val != "":
                hex_parts.append(val)
        hex_data = "".join(hex_parts)
    else:
        hex_data = hex_entry.get().replace(" ", "")
    try:
        # Convert hex string to bytearray for malicious editing
        raw_bytes = bytearray.fromhex(hex_data)

        # Apply malicious checkboxes
        if malicious_options["invalid_function"].get():
            if len(raw_bytes) > 7: raw_bytes[7] = 0x99
        if malicious_options["out_of_range_address"].get():
            if len(raw_bytes) > 9: raw_bytes[8] = 0xFF; raw_bytes[9] = 0xFF
        if malicious_options["incorrect_length"].get():
            if len(raw_bytes) > 5: raw_bytes[4] = 0xFF; raw_bytes[5] = 0xFF
        if malicious_options["extra_bytes"].get():
            raw_bytes += bytes.fromhex("DEADBEEF")
        if malicious_options["corrupted_header"].get():
            if len(raw_bytes) > 3: raw_bytes[2] = 0xFF; raw_bytes[3] = 0xFF

        hex_data = raw_bytes.hex()

        log_entry = f"\n===== SENDING RAW MODBUS TCP PACKET =====\nHex Input: {hex_data}\n"
        output_text.insert(tk.END, log_entry)
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(raw_bytes)
            response = s.recv(1024)
            response_hex = response.hex()
            output_text.insert(tk.END, f"Response Packet (Hex): {response_hex}\n")

            decoded_log = f"\n===== DECODED RESPONSE PACKET =====\n"
            if len(response) >= 9:
                tid = response[0:2].hex()
                pid = response[2:4].hex()
                length = response[4:6].hex()
                uid = response[6:7].hex()
                fcode = response[7]
                decoded_log += f"Byte 0-1: Transaction ID = {tid}\n"
                decoded_log += f"Byte 2-3: Protocol ID = {pid}\n"
                decoded_log += f"Byte 4-5: Length = {length}\n"
                decoded_log += f"Byte 6:   Unit ID = {uid}\n"
                decoded_log += f"Byte 7:   Function Code = {fcode:02X}\n"
                if fcode >= 0x80:
                    exception_code = response[8]
                    msg = {
                        0x01: "Illegal Function",
                        0x02: "Illegal Data Address",
                        0x03: "Illegal Data Value",
                        0x04: "Server Device Failure",
                    }.get(exception_code, "Unknown Error")
                    decoded_log += f"Byte 8:   Exception Code = {exception_code:02X} - {msg}\n"
                elif fcode in [0x01, 0x02]:
                    byte_count = response[8]
                    decoded_log += f"Byte 8:   Byte Count = {byte_count}\n"
                    requested_bits = int(sub_data_entries[1].get(), 16) if use_subfields and sub_data_entries[1].get() else 8
                    shown_bits = 0
                    for byte in response[9:9 + byte_count]:
                        for i in range(8):
                            if shown_bits >= requested_bits:
                                break
                            bit_val = (byte >> i) & 0x01
                            decoded_log += f"Bit {shown_bits + 1} = {bit_val}\n"
                            shown_bits += 1
                elif fcode in [0x03, 0x04]:
                    byte_count = response[8]
                    registers = [str(struct.unpack('>H', response[9+i:11+i])[0]) for i in range(0, byte_count, 2)]
                    decoded_log += f"Byte 8:   Byte Count = {byte_count}\n"
                    decoded_log += f"Byte 9+:  Decoded Registers = {', '.join(registers)}\n"
                elif fcode in [0x05, 0x06, 0x10]:
                    address = int.from_bytes(response[8:10], byteorder='big')
                    value = int.from_bytes(response[10:12], byteorder='big')
                    decoded_log += f"Byte 8-9: Address = {address} (0x{address:04X})\n"
                    decoded_log += f"Byte 10-11: Value = {value} (0x{value:04X})\n"
            logs.append(decoded_log)
            output_text.insert(tk.END, decoded_log)
    except Exception as e:
        error_text = f"Error: {e}\n"
        output_text.insert(tk.END, error_text)
        logs.append(error_text)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)
tk.Button(button_frame, text="Send Packet", command=send_raw_packet).pack(side=tk.LEFT, padx=10)
tk.Button(button_frame, text="Clear Log", command=lambda: output_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=10)
tk.Button(button_frame, text="Export Log", command=lambda: export_log()).pack(side=tk.LEFT, padx=10)

output_text = scrolledtext.ScrolledText(root, width=120, height=22)
output_text.pack(pady=5)

def export_log():
    if not logs:
        output_text.insert(tk.END, "\nNo logs to export.\n")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            f.writelines(logs)
        output_text.insert(tk.END, f"\nLogs saved to: {file_path}\n")

root.mainloop()