import re
import sys

bytes=[]
datavars={}
in_data=False
emitted_re=re.compile('[ 0-9]{3}[0-9] ([0-9a-f]{4}|    ) ([0-9A-F]{2,})')
datavar_re=re.compile('.*\\.data:([0-9a-f]+) ([a-z_]+)')

def append_bytes(s):
    for i in xrange(len(s)/2):
        off=i*2
        bytes.append(chr(int(s[off:off+2],16)))

for l in sys.stdin:
    if '.section .data' in l:
        in_data=True
    if in_data:
        m=emitted_re.match(l)
        if m:
            append_bytes(m.group(2))
        m=datavar_re.match(l)
        if m:
            datavars[m.group(2)]=int(m.group(1),16)
bytes=''.join(bytes)
sys.stdout.write("static char insertcode[]=")
LINE_LEN=20
for i in xrange((len(bytes)+LINE_LEN-1)/LINE_LEN):
    off=i*LINE_LEN
    sys.stdout.write('\n"')
    last_hex=False
    for c in bytes[off:off+LINE_LEN]:
        if (c>=' ' and c<'z' and c!='\\' and c!='"' and
            not(last_hex and c in 'ABCDEFabcdef0123456789')):
            sys.stdout.write(c)
            last_hex=False
        else:
            sys.stdout.write('\\x%02x'%(ord(c)))
            last_hex=True
    sys.stdout.write('"')
sys.stdout.write(';\n')
for k,v in datavars.iteritems():
    print "static size_t offset_%s = 0x%x;"%(k,v)
