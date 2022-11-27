import re

def parse_mem(pid, yaras, outputDir=None, perms="rw"):
    map_file = '/proc/{}/maps'.format(pid)
    mem_file = '/proc/{}/mem'.format(pid)
    map_re = r'(?P<start>[a-f0-9]{1,})\-(?P<end>[a-f0-9]{1,}) (?P<perms>[rwxps\-]{4})'    
    mem_sections = []

    # Get a list of memory regions matching the desired permisions (includes libary space)
    try:
        with open(map_file, 'r') as mapFile:
            for mem_section in mapFile.readlines():
                m = re.search(map_re, mem_section)
                if perms in m.group('perms'): 
                    mem_sections.append({'start':int(m.group('start'), 16), 'end':int(m.group('end'), 16), 'perms': m.group('perms')})
    except:
        print("file open failed, make sure program is running as root!")
        quit()
    # run yaras and save (if selected)
    with open(mem_file, 'rb', 0) as proc_mem:
        for sect in mem_sections:
            proc_mem.seek(sect['start'])
            region = proc_mem.read(sect['end'] - sect['start'])
            matched = scan_region(region, yaras)
            if len(matched) > 0: print("[!] Found matches [!]\nregion start: {start}\nregion end: {end}\nmatches: {matches}".format(start=sect['start'], end=sect['end'], matches=matched))
            if outputDir is not None:
                fname = "{s}-{e}.dump".format(s=str(sect['start']), e=str(sect['end']))
                with open(outputDir+fname, 'wb') as outF:
                    outF.write(region)
            
## pass raw memory region and compiled yaras to scan_region ##
def scan_region(region, rules):
    all_matched = []
    for rule in rules:
        matches = rule.match(data=region)
        if len(matches) > 0: 
            all_matched.append(matches)
    return all_matched




if __name__=="__main__":
    pass