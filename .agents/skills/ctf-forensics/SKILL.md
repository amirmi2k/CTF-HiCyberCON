---
name: ctf-forensics
description: >-
  Activate this skill when a CTF challenge involves file analysis, steganography,
  memory forensics, disk images, network packet captures (PCAP), or hidden data
  extraction. Use for misc/forensics/stego categories.
---

# CTF Forensics & Steganography Skill

## Step 1 — Initial Triage
```bash
file <file>                    # detect real type
xxd <file> | head -20          # inspect magic bytes
strings <file> | grep -i flag  # quick string search
binwalk <file>                 # detect embedded files
exiftool <file>                # metadata
```

## Image Steganography
```bash
# LSB steganography
steghide extract -sf <image> -p ""         # no password
steghide extract -sf <image> -p <password>
stegsolve <image>                           # channel analysis (GUI)
zsteg -a <image.png>                        # PNG/BMP LSB
outguess -r <image.jpg> output.txt

# Spectral analysis (audio/image)
# Open in Sonic Visualizer → spectrogram

# Check image dimensions for hidden data
identify <image>
python3 -c "from PIL import Image; img=Image.open('<image>'); print(img.size, img.mode)"
```

## File Carving & Binwalk
```bash
binwalk -e <file>              # extract embedded files
binwalk --dd='.*' <file>       # extract all signatures
foremost -i <file> -o output/  # file carving
photorec <diskimage>           # photo/file recovery
```

## PCAP / Network Analysis
```bash
# Wireshark filters
# Follow TCP stream → right-click → Follow → TCP Stream
# Look for: HTTP traffic, credentials, file transfers

# tshark CLI
tshark -r <file.pcap> -Y "http" -T fields -e http.request.uri
tshark -r <file.pcap> -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
tshark -r <file.pcap> --export-objects http,./exported/

# Extract files from PCAP
networkMiner <file.pcap>

# Decrypt TLS (if keys available)
# Edit → Preferences → Protocols → TLS → key log file
```

## Memory Forensics
```bash
# Volatility 3
vol3 -f memory.raw windows.info
vol3 -f memory.raw windows.pslist
vol3 -f memory.raw windows.cmdline
vol3 -f memory.raw windows.filescan | grep -i flag
vol3 -f memory.raw windows.dumpfiles --pid <PID> --output-dir ./dump/
vol3 -f memory.raw windows.clipboard
vol3 -f memory.raw windows.registry.hivelist
vol3 -f memory.raw linux.bash  # bash history

# Strings on memory dump
strings -n 8 memory.raw | grep -i "flag{"
strings -n 8 -e l memory.raw | grep -i "flag{"  # UTF-16LE
```

## Disk Image Forensics
```bash
# Mount image
sudo mount -o loop,ro disk.img /mnt/disk

# Autopsy (GUI)
# Or use The Sleuth Kit (TSK)
fls -r disk.img          # list all files
icat disk.img <inode>    # extract file by inode

# Deleted files
tsk_recover disk.img ./recovered/
```

## Audio Steganography
```bash
# Spectrogram (look visually in Audacity/SonicVisualizer)
# Morse code in audio
# DTMF tones → multimon-ng
multimon-ng -t wav -a DTMF audio.wav

# MP3/WAV metadata
exiftool audio.mp3
```

## Structured Output
```json
{
  "agent": "ctf-forensics",
  "file_type": "",
  "hidden_data_found": [],
  "extracted_files": [],
  "flag_candidates": [],
  "confidence": 0.0
}
```
