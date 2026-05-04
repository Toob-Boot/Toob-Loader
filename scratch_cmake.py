import re

cmake_file = r'c:\Users\Robin\Desktop\Toob-Loader\cmake\toob_core.cmake'
with open(cmake_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove all references to chip_config_mock.c
lines = content.split('\n')
new_lines = []
for line in lines:
    if 'chip_config_mock.c' not in line:
        new_lines.append(line)

new_content = '\n'.join(new_lines)
with open(cmake_file, 'w', encoding='utf-8') as f:
    f.write(new_content)

print("Removed chip_config_mock.c from toob_core.cmake")
