from pathlib import Path
p=Path('kernel/src/graphics/framebuffer.rs')
s=p.read_text(encoding='utf-8')
lines=s.splitlines()
counts=[]
count=0
for line in lines:
    count += line.count('{')
    count -= line.count('}')
    counts.append(count)
final = counts[-1]
# find earliest index where min(counts[i:]) == final
for i in range(len(counts)):
    if min(counts[i:]) == final:
        print('earliest index where suffix min == final:', i+1)
        start=max(0,i-5)
        end=min(len(lines), i+15)
        for j in range(start,end):
            print(j+1, counts[j], lines[j])
        break
print('final_count=', final)
