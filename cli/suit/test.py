import subprocess
with open('test.cddl', 'w', encoding='utf-8') as f:
    f.write('''test_map = { my_field }
my_field = (100: uint)''')
subprocess.run([r'C:\Espressif\tools\idf-python\3.11.2\Scripts\zcbor.exe', 'code', '-c', 'test.cddl', '--decode', '-t', 'test_map', '--output-c', 'test.c', '--output-h', 'test.h'])
