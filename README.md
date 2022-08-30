# Mothra

*A python based webshell discovery and decoder for static packet captures. Designed to be extended for easy identification and decoding of many webshell families.*

---

## BASIC USAGE: 


`./mothra.py --infile <input pcap> --yaras <path to .yar or yara directory> --mode parse (OPTIONAL) --outfile <path to output file location (csv by default)>` **To parse out the commands run by the webshell if a compatable parser is found**


`./mothra.py --infile <input pcap> --yaras <path to .yar or yara directory> --mode search` **To search the pcap for evidence of webshell based on yara**

---
  
Mothra utilises pre-written YARA rules for identification of uploaded webshells and a module based decoding structure to allow for seamless creation of custom decoders

## currently supported webshells
- Godzilla in PHP mode B64 XOR mode

