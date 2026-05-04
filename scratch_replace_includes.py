import os

files = []
for root, _, fs in os.walk('c:/Users/Robin/Desktop/Toob-Loader'):
    for f in fs:
        if f.endswith('.c') or f.endswith('.h'):
            files.append(os.path.join(root, f))

count = 0
for file in files:
    try:
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
        if '#include "boot_config_mock.h"' in content:
            new_content = content.replace('#include "boot_config_mock.h"', '#include "generated_boot_config.h"')
            with open(file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            count += 1
    except Exception as e:
        pass
print('Replaced in', count, 'files.')
