lines = open('scripts/run.ps1', encoding='utf-8').read().splitlines()
suffix = lines[309:]
text = '\n'.join(suffix)
print('suffix lines:', len(suffix))
print('open {:', text.count('{'))
print('close }:', text.count('}'))
print('open (:', text.count('('))
print('close ):', text.count(')'))
print('quotes:', text.count('"'), text.count("'"))