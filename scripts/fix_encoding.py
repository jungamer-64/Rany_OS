#!/usr/bin/env python3
import os
from pathlib import Path

# Try decoding using these encodings in order when file is not valid utf-8
encodings = ['utf-8', 'cp932', 'shift_jis', 'euc_jp', 'latin-1']

root = Path('.')
changed = []
for p in root.rglob('*.rs'):
    b = p.read_bytes()
    try:
        b.decode('utf-8')
        # valid utf-8
        continue
    except Exception:
        # try other encodings
        for enc in encodings[1:]:
            try:
                s = b.decode(enc)
                # Successful decode: write back as utf-8
                print(f"Converting {p} from {enc} -> utf-8")
                backup = p.with_suffix(p.suffix + '.orig')
                if not backup.exists():
                    backup.write_bytes(b)
                # write utf-8 (preserve newline style)
                p.write_text(s, encoding='utf-8')
                changed.append((p, enc))
                break
            except Exception:
                continue
        else:
            print(f"Failed to decode {p} in known encodings; skipping")

print(f"Converted {len(changed)} files")
for p,enc in changed:
    print(p, enc)
