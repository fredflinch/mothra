#!/usr/bin/python3

from http.client import responses
from scapy.all import *
from scapy.layers.http import *
import yara, sys, argparse, glob, csv 
from parsers import *
from libs.memparser import parse_mem
from libs.deploycore import autodeploy


def load_pcap(pcap_file):
    pcap = rdpcap(pcap_file)    
    return pcap

def compile_yaras(yara_path):
    if ".yar" in yara_path:
        rules = [yara.compile(filepath=yara_path)]
    else: 
        rules = []
        yaras = glob.glob(yara_path+'/*.yar')
        for yar in yaras:
            rules.append(yara.compile(filepath=yar)) 
    return rules

def search(yara_path, pcap, auto):
    m = []
    rules = compile_yaras(yara_path)
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
                v = p.decode(raw(packet[HTTP].payload).decode('utf8', errors='ignore'))
                if (v != 0):
                    if v[0] == "req":  requests.append(v[1])
                    if v[0] == "resp": responses.append(v[1])
    
    return [requests, responses]


## TODO: saving creates a weird csv -- gotta fix
def save_csv(outfile, cols):
    if (len(cols[0]) - len(cols[1]) >= 0):
        for x in range(0, (len(cols[0]) - len(cols[1]))):
            cols[1].append('')
    else:
        for x in range(0, (len(cols[1]) - len(cols[0]))):
            cols[0].append('')
      
    with open(outfile, "w", newline="\n") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, escapechar='\\', delimiter=',', quotechar='\"')
        for x in range(0, len(cols[0])):
            writer.writerow([cols[0][x], cols[1][x]])

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
    p.add_argument("-m", "--mode", help="Modes: search, parse, memscan, deploy")
    p.add_argument("--remoteaddr", help="Remote address to deploy mothraballs")
    p.add_argument("--remoteport", help="Remote SSH port for deployment")
    p.add_argument("--runops", help="Any options or modifiers to run mothraball with")
    p.add_argument("--auth", help="auth in format user:pass OR user:keyfile")
    p.add_argument("-b", "--ball", help="Ball to deploy\nOptions: scan, test")
    p.add_argument("--pid", help="Process ID of webserver to scan")

    args = p.parse_args()
    del p
    
    parsers = build_parsers()

    if ((args.infile is not None) and (args.mode=="search") and (args.yaras is not None)):
        search(args.yaras, load_pcap(args.infile), False)
    elif ((args.infile is not None) and (args.mode=="parse") and (args.yaras is not None) and args.outfile is None):
        pcap = load_pcap(args.infile)
        decoder = search(args.yaras, pcap, True)
        data = decode_data(pcap, decoder, None)
        print(data)        
    elif ((args.infile is not None) and (args.mode=="parse") and (args.yaras is not None) and (args.outfile is not None)):
        pcap = load_pcap(args.infile)
        decoder = search(args.yaras, pcap, True)
        save_csv(args.outfile, decode_data(pcap, decoder, None))
    elif((args.mode=="memscan") and args.pid and (args.yaras is not None)):
        parse_mem(args.pid, compile_yaras(args.yaras), args.outfile)
    elif((args.mode=="deploy") and (args.remoteaddr is not None) and (args.ball is not None)):
        remotehost, sshport, ball = args.remoteaddr, 22, args.ball 
        if (args.remoteport is not None): sshport = args.remoteport
        user, authsnd = args.auth.split(":")[0], args.auth.split(":")[1]
        if ('.pem' in authsnd): mode='key'
        else: mode="password"
        autodeploy(ball=ball, runop=args.runops, host=remotehost, user=user, auth=authsnd, mode=mode)
        ## TODO: ADD Server start up for scan results - needed if shifting to velociraptor for remote deploy?##
    else:
        print("Error -- please see help with \'-h\'")