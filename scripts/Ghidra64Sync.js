var ghidra = require('Ghidra64SyncConfig.js');

var currGameCfgName = "";
var config = ghidra.readConfig();

var GHIDRA_HOST = "127.0.0.1";
var GHIDRA_PORT = parseInt(config.GHIDRA_PORT) || 12345;
var COMMAND_PORT = parseInt(config.COMMAND_PORT) || 12346;
var ROM_OFFSET = 0x0; 
var JUMP_INTSR = "jump"
var MEM_INTSR = "mem"
var JMPNO_INTSR = "jumpno"
var SYNC_OFFSET_INSTR = "syncoffset"
console.log("Ghidra64Sync Started.");


function syncWithGhidra(syncOffsetOnly) {
    var ramPc = cpu.pc;
    var romAddr = (ramPc + ROM_OFFSET) >>> 0;
    var addrStr = "0x" + romAddr.toString(16) + "\n";
    try {
        var client = new Socket();
        client.connect(GHIDRA_PORT, GHIDRA_HOST);
        client.on('connect', function() {
            if(syncOffsetOnly) {
                client.write(SYNC_OFFSET_INSTR + ":" + ROM_OFFSET + "\n");
            } else{
                client.write(JUMP_INTSR + ":" + addrStr+"\n");
            }
        });
        client.on('data', function(data) {
            client.close();
        });
        client.on('error', function(err) {
        });
    } catch (e) {
        console.log("Sync Error: " + e);
    }
}

var cmdServer = new Server();
cmdServer.on('connection', function(socket) {
    socket.on('data', function(data) {
        //console.log("Received Command: " + data);
        var str = data.toString().trim().toLowerCase();
        var cmd = str.split(":")[0];
        var data = str.split(":")[1];

        if (cmd === JUMP_INTSR) {
            debug.showcommands(parseInt(data, 16));
        }
        else if (cmd === MEM_INTSR) {
            debug.showmemory(parseInt(data, 16));
        }
        else if (cmd === SYNC_OFFSET_INSTR) {
            syncWithGhidra(true);
        }
        else {
            console.log("Unknown Command recv: " + cmd + "\n");
        }
    });
});


function applyROMConfig() {
    currGameCfgName=pj64.romInfo.fileName;
    var gameConfigs = ghidra.readGameConfig();
    var cfg = gameConfigs[currGameCfgName];
    try {
        console.log("Got config for " + currGameCfgName + ": " + cfg.OFFSET);
        ROM_OFFSET = parseInt(cfg.OFFSET, 16) || 0x0;
    } catch (error) {
        console.log("No config for " + currGameCfgName + ", using default offset 0x0.");
    }
    syncWithGhidra(true);
}

applyROMConfig();
cmdServer.listen(COMMAND_PORT);

function onEmulatorStateChange(event) {
    switch (event.state) {
        case EMU_STARTED:
            applyROMConfig();
            console.log("Loaded ROM: " + currGameCfgName);
            break;
        case EMU_DEBUG_PAUSED:
            syncWithGhidra();
            break;
        case EMU_RESUMED:
            if(currGameCfgName === "") {
                currGameCfgName=pj64.romInfo.fileName;
                applyROMConfig();
            }
            break;
    }
}

events.onstatechange(onEmulatorStateChange);
script.keepalive(true);
