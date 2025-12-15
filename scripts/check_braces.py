from pathlib import Path
p=Path('kernel/src/graphics/framebuffer.rs')
count=0
first_neg=None
with p.open(encoding='utf-8') as f:
    for i,line in enumerate(f, start=1):
        count += line.count('{')
        count -= line.count('}')
        if first_neg is None and count<0:
            first_neg=(i,count,line.rstrip())
print('final_count=',count)
if first_neg:
    print('first negative at',first_neg)
else:
    print('no negative prefix')
# Print context around where the count is highest (possible missing closing brace)
with p.open(encoding='utf-8') as f:
    lines=f.readlines()
# find max prefix count
count=0
maxc=(0,0)
for i,line in enumerate(lines, start=1):
    count += line.count('{')
    count -= line.count('}')
    if count>maxc[0]:
        maxc=(count,i)
print('max prefix count',maxc)
# print nearby lines
start=max(0,maxc[1]-10)
end=min(len(lines),maxc[1]+10)
print('Context around max prefix:\n')
for i in range(start,end):
    print(i+1, lines[i].rstrip())
