# Modbus Client (Educational Modbus TCP Packet Crafter)

This project provides a GUI-based Modbus TCP client tool written in Python. It is designed **for educational and research use only**. The tool allows users to craft, send, and analyze both standard and malicious Modbus TCP packets to better understand protocol behavior and security.

---

## Features

- **Connect to a Modbus TCP server** by specifying IP and port.
- **Manually craft raw Modbus TCP packets** (hex editor).
- **Structured field mode**: Fill out fields like Transaction ID, Protocol ID, Function Code, etc.
- **Predefined malicious packets**: Instantly load commonly used attack/malformation payloads.
- **Malicious crafting options**: Toggle invalid function code, out-of-range address, incorrect length, extra payload bytes, or corrupt headers.
- **Live response decoding**: View raw response in hex and parsed form.
- **Log all transactions** with option to export log.
- **Cross-platform** (Windows, Linux, macOS, Python 3.7+).

---

## Screenshots

*Add actual screenshots to your `images/` folder and update file names below.*

![Screenshot1](images/screenshot1.png)  
*Main application window.*

![Screenshot2](images/screenshot2.png)  
*Structured packet fields view.*

![Screenshot3](images/screenshot3.png)  
*Malicious crafting options.*

---

## Installation

### **Requirements**

- Python **3.7+**
- `tkinter` (usually included, but may need `sudo apt-get install python3-tk` on Linux)
- `scapy`
- `pymodbus` (optional, for server simulation)
- `typing-extensions`

**Quick Install:**
#cmd/terminal
pip install -r requirements.txt


**Manual Install:**
#cmd/terminal
pip install tk scapy pymodbus typing-extensions

**Usage**
1. Start a test Modbus server (e.g., with pymodbus, ModbusPal, or other simulator).

2. Run the client:
    #cmd/terminal
    python src/modbus_client.py

3. Enter the server IP and port, click Connect.

4. Craft your packet using raw hex or structured fields.

5. (Optional): Apply malicious crafting options or load a predefined packet.

6. Click Send Packet.

7. View response (hex and decoded) and analyze log.

8. Export log if needed.

Example Packets and Their Effects
1. Write Single Coil (ON):
    Packet: 0001 0000 0006 01 05 0001 FF00
    Breakdown: Transaction=0x0001, Protocol=0x0000, Length=6, Unit=0x01, Function=0x05 (Write Coil), Address=0x0001, Value=0xFF00 (ON).
    Effect: Turns coil #1 ON. On a real system, this could open a circuit breaker, start a motor, or activate a valve
    trustwave.com

2. Write Single Coil (OFF):
    Packet: 0002 0000 0006 01 05 0001 0000
    Same as above but Value=0x0000, turns coil #1 OFF (deactivating the device).

3. Write Holding Register:
    Packet: 0003 0000 0006 01 06 0002 000A
    Function 0x06, Register Address 2, Value 10. Changes a critical setpoint. For instance, setting a voltage or speed parameter. An attacker changing registers could destabilize processes
    trustwave.com

4. Invalid Function Code:
    Packet: 0004 0000 0006 01 90 0001 0001
    Function=0x90 is not standard. The slave will respond with an exception: Function=0x90+0x80=0x110 (trimmed to 0x90 in one byte) and Exception Code=0x01 (Illegal Function)
    ni.com
    . This shows how malformed requests are rejected.

5. Length Mismatch / Corrupted Header:
    Packet: 0005 0000 0007 01 05 0001 FF00 AA (Length=7 but only 6 bytes of data + an extra 0xAA).
    Effect: The server detects the framing error and ignores the packet
    ni.com
    . No response is given, simulating a dropped/ignored request.

For more examples or use the GUI’s Screen.

Responsible Use and Disclaimer
    This tool is provided for educational and research purposes only. It should be used on systems you own or have permission to test. Unauthorized tampering with Modbus devices can cause physical damage or safety hazards. Users must follow ethical guidelines and all applicable laws. The developers assume no responsibility for misuse. Always test in isolated lab environments and inform stakeholders before conducting experiments. By using this software, you agree to use it ethically and responsibly.


License
    This project is licensed under the MIT License.

Contributing
    Pull requests and bug reports welcome. Open an issue or submit a PR!

Folder Structure
    modbus-client/
    │
    ├─ src/                # Python scripts (main GUI)
    ├─ images/             # Place GUI screenshots here
    ├─ requirements.txt    # Python dependencies
    ├─ README.md           # This file
    └─ LICENSE             # MIT License

Acknowledgements
    Modbus protocol: modbus.org
    Educational security testing resources