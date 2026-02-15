# Ghidra64Sync
Sync the debugger in Project64 with Ghidra  
Features:  
- Live instruction syncing when manually selecting, stepping, or hitting a breakpoint in PJ64
- Per-Game Offset so decompressed roms in Ghidra can line up with compressed roms in PJ64
![Demo](https://i.imgur.com/LLxPv1F.gif)

# Instructions
Note: This script is configured to work fully with **Project64 Dev-4.0.0-6642-38986fe** [(Wayback Mirror)](https://web.archive.org/web/20260215041359/https://www.pj64-emu.com/file/project64-win32-dev-4-0-0-6642-38986fe/)  
(It will partially work with others, just not the live syncing when selecting instructions)  
1. Drag and merge the scripts and config folder into the root folder of your Project64 directory  
2. Add a script directory in Ghidra and set it to Project64's Scripts folder  
3. Run Ghidra via **pyghidraRun.bat** in your Ghidra install folder within the "support" folder  
4. In Ghidra's script manager, run "Ghidra64Sync.py"  
5. Load a ROM in Project64, and run Ghidra64Sync.js in Project64's Script window  

# Configuration
- If the file in Ghidra differs from the file in Project64 by some offset, you can set a per-game offset in `Config/ghidraSync/perGameConfig.json` (The offset is applied as follows PJ64_Address+OFFSET --> Ghidra Address)
- Listen/Server ports can be configured in `Config/ghidraSync/config.txt`

# Misc Notes
- How do I find the offset I need?
    - Find your function in PJ64's debugger and right click an instruction to view memory, copy some memory and search for it in Ghidra. Note the addresses of both, and the difference is your offset. Remember, PJ64_Address+OFFSET-->Ghidra Address
- I want to use this in a specific version of PJ64, how can I?
    - Find the pointer to the string of the top address in the commands window, (the one that updates when you scroll) and set addr1 and ptr1 accordingly in Ghidra64Sync_MemMng.py

# To do
- Sync breakpoint addition/removal between Ghidra and Project64
- Add an extra sync option so clicking an instruction in Ghidra will auto-jump to the instruction in PJ64 
