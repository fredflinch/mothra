from http.client import responses
from scapy.all import *
from scapy.layers.http import *
import yara 
import sys
import argparse
import glob 
from parsers import *
import csv

def load_pcap(pcap_file):
    pcap = rdpcap(pcap_file)    
    return pcap

def search(yara_path, pcap, auto):
    m = []
    if ".yar" in yara_path:
        rules = [yara.compile(filepath=yara_path)]
    else: 
        rules = []
        yaras = glob.glob(yara_path+'/*.yar')
        for yar in yaras:
            rules.append(yara.compile(filepath=yar)) 
    for packet in pcap:
        for rule in rules:
            matches = rule.match(data=raw(packet))
            if len(matches) > 0: 
                print("[!] found {} [!]".format(matches[0]))
                print("likely uploader: {}:{} -> {}:{}".format(packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport ))
                m.append((matches[0], raw(packet)))
    if auto:
        if len(m) > 1: print("Multi shell support not available, defaulting to first shell found")
        p = auto_get_parser(m[0][0], parsers, m[0][1].decode('utf8', 'ignore'))
        if p!=0: 
            return p
        else:
            print("auto mode failed...") 
            return 0

def decode_data(pcap, p, filters):
    requests  = ['requests']
    responses = ['responses']

    for packet in pcap:
        if filters is not None:
            if IP in packet and TCP in packet and HTTP in packet and (packet[IP].src in filters['src'] and packet[IP].dst in filters['dst'] and packet[IP].sport in filters['sport'] and packet[IP].dport in filters['dport']):
                v = p.decode(raw(packet[HTTP].payload).decode('utf8'))
                if (v != 0):
                    if v[0] == "req":  requests.append(v[1])
                    if v[0] == "resp": responses.append(v[1])
        else:
            if IP in packet and TCP in packet and HTTP in packet:
                v = p.decode(raw(packet[HTTP].payload).decode('utf8'))
                if (v != 0):
                    if v[0] == "req":  requests.append(v[1])
                    if v[0] == "resp": responses.append(v[1])
    
    return [requests, responses]


## TODO: saving creates a weird csv -- gotta fix
def save_csv(outfile, cols):
    with open(outfile, "w", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_NONE, escapechar='/', delimiter=',', quotechar='')
        writer.writerows(cols)

def auto_get_parser(match, parsers, shell):
    for key in parsers.keys():
        if str(match).lower() in key:
            if "automagic" in dir(parsers[key]):
                am = parsers[key].automagic(shell)
                if am != 0: return am
            print("Parser found! however no automagic method exists.\nManually recover required components and run with --mode manual --decoder {}".format(key))
        else:
            print("No auto parser exists for match, try specifying manually if parser is known")
    return 0
        
def build_parsers():
    parse_dict = {}
    moduleName = "parsers"
    for key in sys.modules.keys():
        if key.split('.')[0] == moduleName and len(key) > len(moduleName): 
            parse_dict[key] = sys.modules[key]
    return parse_dict
    

if __name__=="__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--infile", help="Input PCAP file for analysis")
    p.add_argument("-o", "--outfile", help="Write the output to the file")
    p.add_argument("-y", "--yaras", help="Input yara file or directory of yara rules")
    p.add_argument("-m", "--mode", help="Modes: search, parse")
    args = p.parse_args()
    del p
    
    parsers = build_parsers()

    if ((args.infile is not None) and (args.mode=="search") and (args.yaras is not None)):
        search(args.yaras, load_pcap(args.infile), False)
    elif ((args.infile is not None) and (args.mode=="parse") and (args.yaras is not None) and args.outfile is None):
        pcap = load_pcap(args.infile)
        decoder = search(args.yaras, pcap, True)
        print(decode_data(pcap, decoder, None))
    elif ((args.infile is not None) and (args.mode=="parse") and (args.yaras is not None) and (args.outfile is not None)):
        pcap = load_pcap(args.infile)
        decoder = search(args.yaras, pcap, True)
        save_csv(args.outfile, decode_data(pcap, decoder, None))
    else:
        print("Error -- please see help with \'-h\'")