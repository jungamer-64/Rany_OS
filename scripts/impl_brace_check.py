from pathlib import Path
p=Path('kernel/src/graphics/framebuffer.rs')
s=p.read_text(encoding='utf-8')
lines=s.splitlines()
start=None
for i,line in enumerate(lines, start=1):
    if 'impl Framebuffer {' in line:
        start=i
        break
if not start:
    print('impl Framebuffer not found')
    raise SystemExit(1)
count=0
for i,line in enumerate(lines[start-1:], start=start):
    count += line.count('{')
    count -= line.count('}')
    if i % 50 == 0:
        print(i, 'count=',count)
print('final count in impl-from-start', count)
print('\nTail context:')
for i in range(max(len(lines)-20,0), len(lines)):
    print(i+1, lines[i])
