import sys
from collections import defaultdict

# Constants

FIRST = 5
IRPHOOK = 5
IDTHOOK = 5
TRACK = 5
BOOT = 5
COMM = 5
SUS = 5
OBFUSCATION = 5
DKOM_constant = 5

# Threshold

SUB_DE = 5

# Variables

# These appear to be accumulators for computed values
# returned in the report.

IRP_hook = 0
Hook = 0
SSDT_score = 0
idt_hook = 0
inject = 0
notified = 0
env = 0
multip = 0
recon = 0
anti = 0
s_check = 0
obfuscation = 0
suspectancy = 0
DKOM = 0
w_protection = 0
dispatch_routines = 0
Entry_sub_count = 0
user_commS = 0
commS = 0
Filter = 0
Boot = 0
Track_process = 0
Raise = 0
signal = 0
Track_file = 0
File = 0
fs = 0
net = 0
reg = 0
section = 0
dev_port = 0
dev_system = 0
constant = 0
HW = 0
str_count = 0
OWN_net = 0
str_activity = 0
General_none_e = 0
file_name = 0
MJ_IRP = 0
MJ_loop = 0
allocation_ratio = 0
Allocation = 0
dis_Allocation = 0
IOGetDeviceOb = 0
Dynamic = 0
mutex = 0
Mdl = 0
CR = 0
Boot = 0
mbr = 0
Pi = 0
asyn_PC = 0
device_count = 0
SMM = 0
Int_cont = 0
DMA = 0
sys_manipulate = 0
device = 0
DPC = 0
Synch = 0
thread = 0
port_dev = 0
access = 0
att_device = 0
DriverEntry_size = 0
ow = 0
awake = 0

Entry_sub = defaultdict(lambda: None)
alloc = defaultdict(lambda: None)
dis_alloc = defaultdict(lambda: None)

# Globals --- these are initialized on program start, and are not
# accumulators returned in the report.

# The filename global variable contains the name of the file this
# program is being run on.

filename = sys.argv[1]
device_N = "F"
APIcount = 0
status = 0
io_get_device_ob = 0
in_DriverEntry = 0
IRP_counter = 0
String_entropy = 1
lines = 0
API = "NULL"
current_routine = ""
l = []
string = ""
devicename = ""

from dependencies.functions import *
from dependencies.device_types import *
from dependencies.entropy import *
from dependencies.clusters import *


import re
import sys

# This is the first subroutine run in the course of the program, so
# the authors clearly ided to call it "first" as a result of that
# fact. It opens the input file ...

def first():
    global filename, in_DriverEntry, Entry_sub, Entry_sub_count
    global file_name, status, DKOM_suspend, mbr_suspect
    global st, openedFile
    openedFile = open(filename, "r")
    for line in openedFile.readlines():
        if re.search(r'__stdcall\ DriverEntry\(', line):
            in_DriverEntry = 1
            Entry_sub['DriverEntry'] = 1
        elif in_DriverEntry == 1:
            if re.search(r"call\tsub", line):
                l = re.split(r"sub_", line)
                Entry_sub["sub_" + l[1]] = 1
                Entry_sub_count += 1
            elif re.search(r"call\tloc", line):
                l = re.split('loc_', line)
                Entry_sub['loc_' + l[1]] = 1
                Entry_sub_count += 1
        if re.search(r"\tendp", line):
            l = re.split(r"\t", line)
            r = l[0]
            if r == "DriverEntry":
                in_DriverEntry = 0
    openedFile.close()
    openedFile = open(filename, "r")
    f = re.split(r"\/", filename)
    size = len(f) - 1
    file_name = f[size]
    DKOM_suspend = 0
    mbr_suspect = 0

## This seems to handle the portion of the routine handling variables
## in the kernel drivers. 

def VAR_handle():
    global DesiredAccess, cmp_constant
    global API_found, lines
    global st
    API_found = 0
    lines += 1
    if re.search(r"^push.*DesiredAccess$", st):
        l = re.split(r"push", st)
        d = re.split(r";", l[1])
        DesiredAccess = d[0]
    if re.search(r"^cmp ", st):
        l = re.split(r"\,",st)
        l[1] = re.sub(r"[\x0A\x0D]", "", l[1])
        if re.search(r"h", l[1]):
            ll = re.split(r"h", l[1])
            cmp_constant = ll[1:]
        else:
            cmp_constant = "INVALID"
        

def find_current_routine():
    global current_routine
    global st
    if re.search(r"^sub", st):
        l = re.split(r"\t", st)
        current_routine = l[0]
    elif re.search(r"^sub", st):
        current_routine = "INVALID"
    elif re.search(r"DriverEntry", st):
        current_routine = "DriverEntry"

def API_handle():
    global APIcount, API
    global st
    match_list = [r"ds:"+suff for suff in [r"Zw", r"Ke", r"Ks", r"Cm",
                                          r"Ex", r"Hal", r"Io", r"Mm",
                                          r"Ob", r"Po", r"Ps", r"Rtl",
                                          r"Se", r"Ndis", r"Cc", r"Se"]]
    if matches_one_of(st, match_list):
        l = re.split("ds:", st)
        l[1] = re.sub(r"[\x0a\x0D]", "", st)
        API = l[1]
        APIcount += 1

def CONSTANTS_handle():
    global constant, SMM
    global st
    if re.search(" [0-F]*h", st):
        constant += 1
        if re.search(" A[0-F]{7}h", st) or re.search(" B[0-F]{7}h", st):
            SMM += 1

def IRP_handle():
    global Entry_sub, current_routine, cmp_constant
    global DriverEntry_size, MJ_loop, MJ_IRP, IRP_counter
    global user_commS, fs, dispatch_routines, d_routines
    global st
    if Entry_sub[current_routine] == 1:
        DriverEntry_size += 1
        if re.search(r'\*4\+38h', st):
            MJ_loop = "T"
            if cmp_constant != "INVALID":
                MJ_IRP = "0-"+hex(cmp_constant)+MJ_IRP
        elif re.search(r"\[\+\d\d38-\d\d53]h\]", st):
            l = re.split(r"\+", st)
            d = re.split(r"h", l[1])
            # MJ_IRP[c] = d[0]
            IRP_counter += 1
            if d[0] == '71' or d[0] == '70':
                user_commS += 1
            elif d[0] == '6C':
                fs += 1
            MJ_IRP = MJ_IRP + " " + d[0]

    if matches_all_of(st, ["DEVICE_OBJECT", "PIRP", r"\(", r"\)"]):
        dispatch_routines += 1
        d_routines = d_routines + " " + current_routine

def DEVICE_handle():
    global devicename, device_count, device_N
    global suspectancy, String_entropy
    global devicetype, types, undoc_device
    global deviceN
    global st
    if re.search(r"\\\\Device\\\\", st):
        tt = re.split(r"[\"\']", st)
        devicename = devicename + " " + tt[1]
        y = entropy(devicename)
        if y < String_entropy:
            String_entropy = y
        device_count += 1
        device_N = "T"
        if re.search(r"\.|\:",st):
            suspectancy += 1
        if re.search(r"\*", st):
            suspectancy += 1
        if re.search(r"\.\.", st):
            suspectancy += 1
    elif re.search(r"\;\ DeviceType/", st):
        tt = re.split(r"push", st)
        ttt = re.split(r"\t", tt[1])
        devicetype = ttt[1][:-1]
        if device_type[devicetype]:
            types = types + device_type[devicetype]
        else:
            types = types + r" undoc"
            undoc_device += 1
        deviceN = T

def VARIABLES_handle():
    global suspectancy, str_count, General_none_e
    global string_entropy, string
    global st
    search_expr = r"[\\\/\&\.\:\*\'\"\]\[\(\)\&\$\^\#\-\_\,\;\@\ \!\?\+\=]"
    sub_expr = r"(" + search_expr + r"|" + r"[\x20-\x7f])" 
    if re.search(r"db\ \'", st):
        w = re.split(r"\'", st)
        t2 = re.split(r"\'", w[1])
        string = t2[0]
        if re.search(search_expr, string):
            suspectancy += 1
        string = re.sub(search_expr, "", string)
        str_count += 1
        e = entropy(string)
        if e < String_entropy:
            string_entropy = e
        # print("String \"{}\"\n".format(string))
        General_none_e = none_english_extractor(string)
        if not General_none_e:
            General_none_e = 0

def MISC_handle():
    global IOGetDeviceOb, lines, old_line_counter, CONS1
    global IRP_hook, sys_info_class, Allocation
    global dis_Allocation, alloc, mbr_suspect, suspectancy
    global CR, plus, mbr, commS, net, OWN_net, DMA
    global Int_cont, obfuscation, anti, idt_hook, DKOM, DKOM_suspend
    global DKOM_constant, dev_port, dev_system
    global st
    if IOGetDeviceOb and lines-old_line_counter < CONS1:
        if re.search(r"eax, \[eax+8\]", st):
            IRP_hook += 1
    elif re.search(r"SystemInformationClass", st):
        t = re.split(r'\t\t', st)
        tt = re.split(r'\t', t[1])
        sys_info_class = tt[1]
    elif matches_all_of(st, [r"\+70h\]", r"move"]):
        IRP_hook += 0.5
    elif re.search(r"eax, cr0", st):
        CR += 1
    elif re.search("eax, 0FFFEFFFFh", st) and CR > 0:
        CR += 1
    elif re.search("call\tsub\_", st):
        if re.search(current_routine, st):
            if alloc[current_routine] == "T":
                Allocation += 1
            elif dis_alloc[current_routine] == "T":
                dis_Allocation += 1
    elif matches_all_of(st, [r"\[", r"\]", r"\+"]):
        plus =+ 1
    elif re.search(r"Harddisk0", st):
        mbr += 1
        mbr_suspect = 1
    elif re.search(r"\ 7C00h", st) and mbr_suspect == 1:
        mbr += 1
    elif matches_one_of(st, [r"svchost", r"explorer",
                             r"winlogon", r"lsaas", r"krn", r"os", r"win", r"\%"]):
        suspectancy += SUS
    elif API == r"IoGetDeviceObjectPointer":
        commS += 1
        IOGetDeviceOb += 1
        old_line_counter = lines
    elif matches_one_of(st, [r"Ndis", r"Miniport"]):
        OWN_net += 1
        net += 1
    elif re.search(r"DMA controller", st):
        DMA += 1
    elif re.search(r"Interrupt Controller", st):
        Int_cont += 1
    elif re.search(r"analysis failed", st):
        obfuscation += OBFUSCATION
        anti = OBFUSCATION
    elif matches_one_of(st, [r"sidt", r"lidt", r"lgdt", r"sgdt"]):
        idt_hook += IDTHOOK

    elif matches_one_of(st, [r"Flink", r"Blink"]):
        DKOM += DKOM_constant
        DKOM_suspend = 1
    elif (re.search(r"EPROCESS", st) and DKOM_suspend == 1):
        DKOM += DKOM_constant
    elif re.search(r"INT3", st):
        anti += 1
        # print("INT3 detected! (anti analysis)")
    elif re.search(r"ObDereferenceObject", st):
        IRP_hook += 1
    elif matches_one_of(st, [r"READ_PORT", r"WRITE_PORT"]):
        dev_port += 1
    elif re.search(r"Dump_", st):
        dev_port += 1
    elif matches_one_of(st, [r"READ_REGISTER", r"WRITE_REGISTER"]):
        dev_system += 1
        

def SCORE_analysis():
    global track_process, Track_process, track_file, Track_file
    global notified, notify, MDL, Mdl, inject1, injectfs, inject_section, inject
    global SSDT_score, SSDT, hook, Hook, DKOM, Boot, boot, DKOM_cluster
    global security, access, sys_manipulate, system_manipul, filter_cluster, Filter
    global att_device, attache_device, protection, protect
    global write, w_protection, user_communication, user_commS
    global APC, asyn_PC, pipe, Pi, Str, str_activity, net, network_activity
    global File, file_activity, fs_activity, fs, registry_activity, reg
    global section_activity, section, device_activity, device
    global thread_activity, thread, awaken, awake, synchronize, Synch
    global exclusion, mutex, IRQL_raise, Raise, overwrite, ow
    global multi_processor_cluster, multip, dynamic_load, Dynamic
    global anti_analysis, anti, system_reconaissance, recon
    global self_check, random, s_check, suspect, suspectancy
    global DPC_rine, DPC, allocat, Allocation, alloc, current_routine
    global dis_Allocation, dis_alloc, dis_allocat
    global kernel_communication, commS, API, string
    
    if SCORE_analysis_check(track_process):
        Track_process += 1
    elif SCORE_analysis_check(track_file):
        Track_file += 1
    elif SCORE_analysis_check(notify, False):
        notified += 1
    elif SCORE_analysis_check(MDL, False):
        Mdl += 1
    elif (SCORE_analysis_check(inject1)
          or SCORE_analysis_check(inject_fs)):
        inject += 1
    elif SCORE_analysis_check(inject_section):
        inject += 1
        # print("probable patches sections")
    elif SCORE_analysis_check(SSDT):
        SSDT_score += 1
    elif SCORE_analysis_check(hook):
        Hook += 1
    elif SCORE_analysis_check(DKOM_cluster):
        DKOM += 1
    elif SCORE_analysis_check(boot):
        Boot += 1
    elif SCORE_analysis_check(security):
        access += 1
    elif SCORE_analysis_check(system_manipul):
        sys_manipulat += 1
    elif SCORE_analysis_check(filter_cluster):
        Filter += 1
    elif SCORE_analysis_check(attache_device):
        att_device += 1
    elif SCORE_analysis_check(protection):
        protect += 1
    elif SCORE_analysis_check(write):
        w_protection += 1
    elif SCORE_analysis_check(user_communication):
        user_commS += 1
    elif SCORE_analysis_check(APC):
        asyn_PC += 1
    elif SCORE_analysis_check(pipe):
        Pi += 1
    elif SCORE_analysis_check(DMA_cluster):
        Pi += 1
    elif SCORE_analysis_check(Str):
        str_activity += 1
    elif SCORE_analysis_check(network_activity):
        net += 1
    elif SCORE_analysis_check(file_activity):
        File += 1
    elif SCORE_analysis_check(fs_activity):
        fs += 1
    elif SCORE_analysis_check(registry_activity):
        reg += 1
    elif SCORE_analysis_check(section_activity):
        section += 1
    elif SCORE_analysis_check(device_activity):
        device += 1
    elif SCORE_analysis_check(thread_activity):
        thread += 1
    
    elif SCORE_analysis_check(awaken):
        awake += 1
    elif SCORE_analysis_check(synchronize):
        Synch += 1
    elif SCORE_analysis_check(exclusion):
        mutex += 1
    elif SCORE_analysis_check(IRQL_raise):
        Raise += 1
    elif SCORE_analysis_check(overwrite):
        ow += 1
    
    elif SCORE_analysis_check(multi_processor_cluster):
        multip += 1
    elif SCORE_analysis_check(dynamic_load):
        Dynamic += 1
        # print("Run time loading of some kernel components detected by: {}".format(API))
    elif SCORE_analysis_check(anti_analysis):
        anti += 1
    elif SCORE_analysis_check(system_reconaissance):
        recon += 1
    elif SCORE_analysis_check(self_check) or SCORE_analysis_check(random):
        s_check += 1
    elif SCORE_analysis_check(suspect):
        suspectancy += SUS
    elif SCORE_analysis_check(DPC_routine):
        DPC += 1
    elif SCORE_analysis_check(allocat):
        Allocation += 1
        alloc[current_routine] = "T"
    elif SCORE_analysis_check(dis_allocat):
        dis_Allocation += 1
        dis_alloc[current_routine] = "T"
    if SCORE_analysis_check(kernel_communication):
        commS += 1

    API = "NULL"
    string = "NULL"
        
    
    

def score_calc():
    global undoc, undocumented_API, undoc_device
    global Mdl, CR
    global w_protection
    global Allocation, allocation_radio, dis_Allocation
    global Boot, mbr, notified, commS
    global user_commS, Pi
    global asyn_PC
    global env, multip, recon, anti, s_check
    global device_count, suspectancy, MJ_loop
    global dispatch_routines, SMM, Int_cont, DMA
    global str_activity, lines, sys_manipulate
    
   #  undoc = undocumented_API + undoc_device
    w_protection = Mdl + CR
    if Allocation:
        allocation_ratio = dis_Allocation/Allocation
    Boot += mbr
    commS += 0.6 * notified
    user_commS += Pi
    commS += asyn_PC
    env += multip + recon + anti + s_check

    if device_count < 0:
        suspectancy += 1

    if (MJ_loop != "T") != (dispatch_routines <= 0):
        MJ_loop = 3
    elif MJ_loop == "T" and dispatch_routines > 0:
        MJ_loop = 5
    else:
        MJ_loop = 0
    MJ_loop /= 5

    HW=SMM + Int_cont + DMA
    str_activity /= lines
    suspectancy += sys_manipulate

def report1():
    global out_file, file_name
    out = file_name + "_report"
    out_file = open(out, "w+")

def report2():
    global SSDT_score, IRP_hook, inject, Hook, DKOM, w_protection
    global Filter, Boot, HW, File, net, reg, device, fs, DPC
    global Raise, commS, user_commS, Synch, notified, mutex, thread, port_dev, dispatch_routines
    global anti, obfuscation, env, Track_process, Track_file, access
    global Dynamic, att_device, suspectancy, constant, lines, str_activity
    global General_none_e, Entry_sub_count, DriverEntry_size, APIcount
    global String_entropy, lines
    #min-max normalization
    
    SSDT_score_norm=(SSDT_score - 0 )/27
    IRP_hook_norm=(IRP_hook - 0 )/10
    inject_norm=(inject - 0 )/143
    Hook_norm=(Hook - 0 )/69
    DKOM_norm=(DKOM - 0 )/325
    w_protection_norm=(w_protection - 0 )/84
    filter_norm=(Filter - 0 )/12
    boot_norm=(Boot - 0 )/2
    HW_norm=(HW  - 0 )/371
    file_norm=(File - 0 )/21
    net_norm=(net - 0 )/23035
    reg_norm=(reg- 0 )/382
    device_norm=(device - 0 )/14
    fs_norm=(fs - 0 )/7
    DPC_norm=(DPC - 0 )/282
    Raise_norm=(Raise - 0 )/9
    commS_norm=(commS - 5 )/659
    user_commS_norm=(user_commS - 0 )/25
    synch_norm=(Synch - 0 )/59
    notified_norm=(notified - 0 )/132
    mutex_norm=(mutex - 0 )/72
    thread_norm=(thread - 0 )/47
    port_dev_norm=(port_dev - 0 )/830
    dispatch_rines_norm=(dispatch_routines - 0 )/45
    anti_norm=(anti - 0)/2
    obfuscation_norm=(obfuscation - 0 )/1464
    env_norm=(env - 0 )/82
    Track_process_norm=(Track_process - 1 )/1428
    Track_file_norm=(Track_file - 0 )/92
    access_norm=(access - 0 )/85
    Dynamic_norm=(Dynamic - 0 )/54
    att_device_norm=(att_device- 0 )/6
    suspectancy_norm=(suspectancy - 0)/50709
    constant_norm=((constant /lines)- 0.001685454)/0.995583596 
    str_activity_norm=(str_activity - 0 )/0.033075299
    General_none_e_norm=(General_none_e - 0 )/1412513
    Entry_sub_count_norm=(Entry_sub_count - 0 )/353
    DriverEntry_size_norm=(DriverEntry_size - 0 )/110737
    APIcount_norm=(APIcount - 0 )/8713
    String_entropy_norm=(String_entropy - 0 )/0.999495244
    lines_norm=(lines - 0 )/29011150

    print(SSDT_score_norm, IRP_hook_norm, inject_norm, Hook_norm,
          DKOM_norm, w_protection_norm, filter_norm, boot_norm,
          HW_norm, file_norm, net_norm, reg_norm, device_norm,
          fs_norm, DPC_norm, Raise_norm, commS_norm,
          user_commS_norm, synch_norm, notified_norm, mutex_norm,
          thread_norm, port_dev_norm, dispatch_rines_norm,
          anti_norm, obfuscation_norm, env_norm, Track_process_norm,
          Track_file_norm, access_norm, Dynamic_norm,
          att_device_norm, suspectancy_norm, constant_norm,
          str_activity_norm, General_none_e_norm,
          Entry_sub_count_norm, DriverEntry_size_norm,
          APIcount_norm, String_entropy_norm, lines_norm, sep=", ")
    
## Helper functions

def matches_one_of(s, regex_list):
    for regex in regex_list:
        if re.search(regex, s):
            return True
    return False

def matches_all_of(s, regex_list):
    for regex in regex_list:
        if not re.search(regex, s):
            return False
    return True

def grep(regex, string_list):
    return list(filter(lambda s: re.search(regex, s), string_list))

def SCORE_analysis_check(arg, check_length=True):
    global string
    if check_length:
        return (grep(API, arg) or grep("^"+string, arg)) and len(string) > 6
    else:
        return (grep(API, arg) or grep("^"+string, arg))



# Main

if __name__ == "__main__":
    first()
    # report1()
    for st in openedFile.readlines():   # Remember to finish this!!!!
        VAR_handle()
        find_current_routine()
        API_handle()
        CONSTANTS_handle()
        IRP_handle()
        DEVICE_handle()
        VARIABLES_handle()
        MISC_handle()
        SCORE_analysis()

    score_calc()
    report2()
