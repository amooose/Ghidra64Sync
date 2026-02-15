import frida
import ctypes, time
from ctypes import wintypes
import time
import socket
import threading
from ghidra.util.exception import CancelledException

config_dir = getSourceFile().getParentFile().getParentFile().getAbsolutePath()+"\\Config\\ghidraSync\\config.txt"
config = {}
with open(config_dir, "r") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue  # skip blanks/comments
        key, value = line.split("=", 1)
        config[key.strip()] = value.strip()
PJ64SYNC_LISTENER_PORT = int(config["GHIDRA_PORT"])

running = True
localhost = "127.0.0.1"
session = frida.attach("Project64.exe")

script = session.create_script("""
var base = Process.getModuleByName("comctl32.dll").base;
var addr = ptr(base).add(0x19b239);
var baseP =  Process.getModuleByName("Project64.exe").base;                                                           

function hook(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            var addr1 = baseP.add(0x00220084).readPointer();
            var ptr1 = addr1.add(0x1a0).readPointer();
            var ctx = this.context;
            send({
                ebx: ctx.ebx.toString(),
                topaddr: ptr1.toString()
            });
        }
    });
}
                               
hook(addr);                   
""")

def checkHealth():
    pm = currentProgram.getUsrPropertyManager()
    stringMap = pm.getStringPropertyMap("THREAD_KILL_SIGNAL")
    if(stringMap is not None):
        value = stringMap.get(toAddr(0))
        if value == "KILL":
            return False
    return True

def send_cmd(cmd, port=PJ64SYNC_LISTENER_PORT):
    DEST_IP = localhost
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0) 
            s.connect((DEST_IP, port))
            s.sendto(cmd.encode('utf-8'), (DEST_IP, port))
    except Exception as e:
        print(f"Socket Error: {e}")

def on_message(msg, data):
    if msg["type"] == "send":
        payload = msg["payload"]
        ebx = payload.get('ebx', '0')
        addr = payload.get('topaddr', '0')
        jumpaddr = int(addr, 16) + (int(ebx, 16) * 4)
        send_cmd(f"jumpno:0x{jumpaddr:08x}\n")
    elif msg["type"] == "error":
        print(f"Frida Error: {msg.get('description')}")

def run_frida():
    global running
    try:
        script.on("message", on_message)
        script.load()
        print("Ghidra64Sync MemInspector Loaded")
        while running:
            running = checkHealth()
            time.sleep(1)
    except Exception as e:
        print(f"Ghidra64Sync MemInspector Crash: {e}")
    finally:
        print("Ghidra64Sync MemInspector thread shut down.")
        script.unload()
        session.detach()
        monitor.cancel()

t = threading.Thread(target=run_frida)
t.daemon = True 
t.start()
