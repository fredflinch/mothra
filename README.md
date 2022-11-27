# Mothra

*A python based webshell discovery and decoder tool supporting, static packet captures, filesystem analysis (TODO) and linux process memory. Designed to be extended for easy identification and decoding of many webshell families.*

---

## BASIC USAGE: 

**To parse out the commands run by the webshell if a compatable parser is found**

`./mothra.py --infile <input pcap> --yaras <path to .yar or yara directory> --mode parse (OPTIONAL) --outfile <path to output file location (csv by default)>` 



**To search the pcap for evidence of webshell based on yara**

`./mothra.py --infile <input pcap> --yaras <path to .yar or yara directory> --mode search` 


**To search process memory**

`./mothra.py --pid <proc id of webserver/process to inspect> --yaras <path to .yar or yara directory> --mode memscan (OPTIONAL) --outfile <directory to dump proc mem>`

---
  
Mothra utilises pre-written YARA rules for identification of uploaded webshells and a module based decoding structure to allow for easy creation and integration of custom decoders for all sorts of webshells

## currently supported webshells
- Godzilla in PHP mode B64 XOR mode

