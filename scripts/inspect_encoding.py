import sys
p='kernel/src/security/mod.rs'
with open(p,'rb') as f:
    b=f.read()
print('bytes[:120]=',repr(b[:120]))
try:
    b.decode('utf-8')
    print('utf8 ok')
except Exception as e:
    print('utf8 fail',e)
for enc in ['cp932','shift_jis','euc_jp','latin-1']:
    try:
        s=b.decode(enc)
        print(enc,'ok ->',s[:120])
    except Exception as e:
        print(enc,'fail',e)
