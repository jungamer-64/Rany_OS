from pathlib import Path
p=Path('kernel/src/graphics/framebuffer.rs')
s=p.read_text(encoding='utf-8')
count=0
last=None
lines=s.splitlines()
for i,line in enumerate(lines,1):
    count += line.count('{')
    count -= line.count('}')
    if count==2:
        last=i
print('last',last)
print('\nContext:')
start=max(0,last-5)
end=min(len(lines), last+5)
for i in range(start,end):
    print(i+1, lines[i])
