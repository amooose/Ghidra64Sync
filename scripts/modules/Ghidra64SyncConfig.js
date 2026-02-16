
function fileExists(path) {
    try {
        fs.stat(path);
    } catch (e) {
        return false;
    }
    return true;
}

function firstSetup(){
    fs.mkdir("./config/ghidraSync");
    if(!fileExists("./config/ghidraSync/config.txt")) {
        var fd = fs.open("./config/ghidraSync/config.txt", "wb");
        fs.write(fd, "GHIDRA_PORT=12345\nCOMMAND_PORT=12346");
        fs.close(fd);
    }
    if(!fileExists("./config/ghidraSync/perGameConfig.json")) {
        var fd = fs.open("./config/ghidraSync/perGameConfig.json", "wb");
        fs.write(fd, "");
        fs.close(fd);
    }
}

function readConfig() {
    if (!fs.mkdir("./config/ghidraSync/")) {
        firstSetup();
    }
    
    var configData;
    try {
        configData = fs.readfile("./config/ghidraSync/config.txt");
    } catch (e) {
        return {};
    }

    if (!configData || configData.length === 0) {
        console.log("Config file is empty. Using default settings.");
        return {};
    }

    var configData = configData.toString('utf8'); 
    var lines = configData.split("\n");
        var config = {};

        lines.forEach(function(line) {
            var parts = line.split("=");
            if (parts.length === 2) {
                config[parts[0].trim()] = parts[1].trim();
            }
        });
    
    return config;
}

function readGameConfig() {
    var filePath = "./config/ghidraSync/perGameConfig.json";
    var configData;
    try {
        configData = fs.readfile(filePath);
    } catch (e) {
        return {};
    }

    if (!configData || configData.length === 0) {
        return {};
    }

    try {
        var jsonString = configData.toString('utf8');
        return JSON.parse(jsonString);
    } catch (e) {
        console.log("Error parsing JSON: " + e);
        return {};
    }
}

module.exports = {
    firstSetup: firstSetup,
    readConfig: readConfig,
    readGameConfig: readGameConfig,
    version: "1.0"
};
