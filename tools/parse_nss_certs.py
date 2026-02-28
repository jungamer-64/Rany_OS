import sys
import re

def parse_nss(filename):
    with open(filename, 'r') as f:
        content = f.read()
    
    # Split by the start of an object (CKA_CLASS)
    raw_objects = content.split('CKA_CLASS CK_OBJECT_CLASS')
    objects = []
    
    for raw in raw_objects:
        if not raw.strip(): continue
        
        obj = {}
        # Simple regex for single line attributes
        # CKA_LABEL UTF8 "..."
        # CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
        
        label_match = re.search(r'CKA_LABEL UTF8 "([^"]+)"', raw)
        if label_match:
            obj['label'] = label_match.group(1)
        
        if 'CKO_CERTIFICATE' in raw:
            obj['class'] = 'CERT'
            # Find CKA_VALUE MULTILINE_OCTAL ... END
            val_match = re.search(r'CKA_VALUE MULTILINE_OCTAL\n(.*?)\nEND', raw, re.DOTALL)
            if val_match:
                # Octals like \060\202\003
                octals = re.findall(r'\\([0-7]{3})', val_match.group(1))
                obj['value'] = bytes(int(o, 8) for o in octals)
        
        if 'CKO_NSS_TRUST' in raw:
            obj['class'] = 'TRUST'
            if 'CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR' in raw:
                obj['trusted'] = True
                
        if 'label' in obj:
            objects.append(obj)
    return objects

def main():
    objs = parse_nss("/tmp/certdata.txt")
    certs = {o['label']: o['value'] for o in objs if o.get('class') == 'CERT' and 'value' in o}
    trusted = {o['label'] for o in objs if o.get('class') == 'TRUST' and o.get('trusted')}
    
    count = 0
    with open("libs/security/src/root_certs.rs", "w") as f:
        f.write("// Generated from Mozilla certdata.txt\n")
        f.write("#![allow(clippy::all)]\n\n")
        f.write("pub const ROOT_CERTS: &[(&str, &[u8])] = &[\n")
        for label in sorted(trusted):
            if label in certs:
                der = certs[label]
                f.write("    (\"{}\", &[\n".format(label))
                for i in range(0, len(der), 16):
                    chunk = der[i:i+16]
                    f.write("        " + ", ".join("0x{:02x}".format(b) for b in chunk) + ",\n")
                f.write("    ]),\n")
                count += 1
        f.write("];\n")
    print("Generated {} certs".format(count))

if __name__ == "__main__":
    main()
