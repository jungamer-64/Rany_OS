from pathlib import Path
p=Path('kernel/src/graphics/framebuffer.rs')
s=p.read_text(encoding='utf-8')
lines=s.splitlines()
count=0
prefix_counts=[]
for i,line in enumerate(lines, start=1):
    count += line.count('{')
    count -= line.count('}')
    prefix_counts.append((i,count,line))
# Print last 200 lines with counts
for i,c,l in prefix_counts[-200:]:
    print(f"{i:5} {c:3} | {l}")
