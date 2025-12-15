from pathlib import Path
p=Path('kernel/src/graphics/framebuffer.rs')
stack=[]
with p.open(encoding='utf-8', errors='replace') as f:
    for i,line in enumerate(f, start=1):
        for c in line:
            if c=='{':
                stack.append((i,line.strip()))
            elif c=='}':
                if stack:
                    stack.pop()
                else:
                    print('Extra closing brace at',i)
                    # Print some context lines around the extra close
                    with p.open(encoding='utf-8', errors='replace') as g:
                        all_lines = g.readlines()
                        start = max(0, i-5)
                        end = min(len(all_lines), i+5)
                        print('Context around extra close:')
                        for idx in range(start, end):
                            print(f"{idx+1}: {all_lines[idx].rstrip()}")
                    stack.append(('EXTRA_CLOSE',i))
                    break

if stack:
    print('Unmatched opening brace(s):')
    for s in stack:
        print(s)
else:
    print('All braces matched')
