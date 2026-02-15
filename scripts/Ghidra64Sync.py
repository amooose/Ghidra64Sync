# @runtime Jython
import socket
import threading
import time, subprocess, sys, os
from ghidra.util.task import TaskMonitor
from java.lang import Runnable
from javax.swing import SwingUtilities
from ghidra.app.plugin.core.decompile import DecompilerActionContext
from ghidra.app.util.viewer.field import BrowserCodeUnitFormat
from docking.action import DockingAction
from docking.action import MenuData
from docking.action import ToggleDockingAction
from ghidra.app.context import ListingActionContext
from java.net import Socket, InetSocketAddress
from java.io import PrintWriter
from java.net import ConnectException
import subprocess
import threading
import sys, os
import time
import __main__

ROM_OFFSET = 0x0
should_sync = True

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
PJ64SYNC_SENDER_PORT = int(config["COMMAND_PORT"])

print("Config directory:", config_dir)
print("Listener Port:", PJ64SYNC_LISTENER_PORT)
print("Sender Port:", PJ64SYNC_SENDER_PORT)

def storeVar(var):
    MAP_NAME = "THREAD_KILL_SIGNAL"
    stringMap = pm.getStringPropertyMap(MAP_NAME)
    if stringMap is None:
        stringMap = pm.createStringPropertyMap(MAP_NAME)
    dummy_addr = toAddr(0) 
    txId = currentProgram.startTransaction("Update Shared Property")
    try:
        stringMap.add(dummy_addr, var)
        currentProgram.endTransaction(txId, True)  
    except Exception as e:
        currentProgram.endTransaction(txId, False) 
        print("Error:", e)

pm = currentProgram.getUsrPropertyManager()
storeVar("KILL")
time.sleep(2)
storeVar("")
runScript("Ghidra64Sync_MemMng.py")


def pjprint(msg):
    print("[PJ64DebugSync] " + msg)

def send_cmd(cmd,port=PJ64SYNC_LISTENER_PORT,optinfo=None):
    client = None
    try:
        client = Socket()
        client.connect(InetSocketAddress("127.0.0.1", port), 500)
        out = PrintWriter(client.getOutputStream(), True)
        out.print(cmd)
        out.flush()
        if(cmd != "STOP"):
            if optinfo is not None:
                cmd = cmd + " | " + str(optinfo)
            pjprint("Sent command to Project64: " + cmd)
    except (Exception, ConnectException, socket.error) as e:
        pjprint("PJ64 GhidraSync not reachable yet, waiting for connection...")
    finally:
        if client:
            client.close()

actions = ["Jump in Project64", "Show in Memory", "Sync", "Breakpoint"]
tool = state.getTool()
existing_actions = tool.getAllActions()
for action in existing_actions:
    if action.getName() in actions:
        tool.removeAction(action)



class PJ64ActionWrapper:
    def __init__(self, name, owner, is_toggle=False, subname=None):
        self.name = name
        self.owner = owner
        self.subname = subname
        
        if self.name == "Breakpoint":
            self.action = self._create_bkp_action()
        elif is_toggle:
            self.action = self._create_toggle_action()
        else:
            self.action = self._create_standard_action()

    def _create_bkp_action(self):
        class BkpAction(DockingAction):
            def actionPerformed(derived_self, context):
                self.send_task(context, is_checked=None)
        
        a = BkpAction(self.name, self.owner)
        a.setPopupMenuData(MenuData([self.owner, self.name, self.subname]))
        return a

    def _create_standard_action(self):
        class SimpleAction(DockingAction):
            def actionPerformed(derived_self, context):
                self.send_task(context, is_checked=None)
        
        a = SimpleAction(self.name, self.owner)
        a.setPopupMenuData(MenuData([self.owner, self.name]))
        return a

    def _create_toggle_action(self):
        class CheckboxAction(ToggleDockingAction):
            def actionPerformed(derived_self, context):
                self.send_task(context, is_checked=derived_self.isSelected())
        
        a = CheckboxAction(self.name, self.owner)
        a.setPopupMenuData(MenuData([self.owner, self.name]))
        a.setSelected(True)
        return a

    def send_task(self, context, is_checked=None):
        if(self.name == "Sync"):
            if is_checked is not None:
                global should_sync
                if is_checked:
                    should_sync = True
                else:
                    should_sync = False
            return
        addr = context.getAddress()

        
        addr_hex = addr.getOffset()-ROM_OFFSET
        optinfo = ""
        cmd = ""
        if(self.name == "Jump in Project64"):
            cmd = "jump"
        if(self.name == "Show in Memory"):
            cmd = "mem"
        optinfo = "0x{:08x}".format(addr.getOffset())
        payload = "{}:0x{:08x}".format(cmd, addr_hex)
        send_cmd(payload,PJ64SYNC_SENDER_PORT,optinfo=optinfo)


jump_now = PJ64ActionWrapper("Jump in Project64", "Project64", is_toggle=False)
tool.addAction(jump_now.action)

bkp_add = PJ64ActionWrapper("Breakpoint", "Project64", is_toggle=False, subname="Add Breakpoint")
tool.addAction(bkp_add.action)

bkp_rem = PJ64ActionWrapper("Breakpoint", "Project64", is_toggle=False, subname="Remove Breakpoint")
tool.addAction(bkp_rem.action)

auto_sync = PJ64ActionWrapper("Show in Memory", "Project64", is_toggle=False)
tool.addAction(auto_sync.action)

auto_sync = PJ64ActionWrapper("Sync", "Project64", is_toggle=True)
tool.addAction(auto_sync.action)

def sync_decompiler(address):
    tool = state.getTool()
    provider = tool.getComponentProvider("Decompiler")
    if provider:
        provider.goTo(currentProgram, ghidra.program.util.ProgramLocation(currentProgram, address))

class GhidraServer:
    def __init__(self, port=PJ64SYNC_LISTENER_PORT):
        self.port = port
        self.running = True

    def run_on_ui_thread(self, data):
        class GuiJump(Runnable):
            def run(self):
                info = data.split(":")
                instruct = info[0]
                idata = info[1]
                
                try:
                    if not should_sync:
                        return
                    if instruct == "syncoffset":
                        global ROM_OFFSET
                        ROM_OFFSET = int(idata)
                        print("Synced Offset from gameConfig file: 0x{:08x}".format(ROM_OFFSET))
                    if "jump" in instruct:
                        target = toAddr(idata)
                        if(instruct == "jumpno"):
                            target = target.add(ROM_OFFSET)
                        goTo(target) 
                        tool = state.getTool()
                        decomp_provider = tool.getComponentProvider("Decompiler")
                        if decomp_provider:
                            loc = ghidra.program.util.ProgramLocation(currentProgram, target)
                            decomp_provider.goTo(currentProgram, loc)
                except Exception as e:
                    pjprint("Sync Error: {}".format(e))
        
        SwingUtilities.invokeLater(GuiJump())

    def start_listener(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind(('localhost', self.port))
            server_socket.listen(5)
        except Exception as e:
            send_cmd("STOP")
            pjprint("Rebooting server")
            time.sleep(1) 
            server_socket.bind(('localhost', self.port))
            server_socket.listen(5)
        try:
            pjprint("Background Server Started on port {}...".format(self.port))
            send_cmd("syncOffset",PJ64SYNC_SENDER_PORT)
        except (Exception, ConnectException, socket.error) as e:
            pjprint("PJ64 GhidraSync not reachable yet, waiting for connection...")
        while self.running:
            try:
                server_socket.settimeout(1.0) 
                try:
                    conn, addr = server_socket.accept()
                except socket.timeout:
                    continue

                data = conn.recv(4096).strip()
                if data:

                    if data.upper() == "STOP":
                        self.running = False
                    else:
                        self.run_on_ui_thread(data)

                conn.close()
            except Exception as e:
                if data.upper() != "STOP":
                    pjprint("Server Error: {}".format(e))
        
        server_socket.close()
        pjprint("Old Server Instance Stopped.")
        monitor.cancel()

server = GhidraServer(PJ64SYNC_LISTENER_PORT)
t = threading.Thread(target=server.start_listener)
t.daemon = True 
t.start()
