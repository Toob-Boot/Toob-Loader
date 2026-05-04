import os
import re

for root, _, fs in os.walk('c:/Users/Robin/Desktop/Toob-Loader'):
    for f in fs:
        if f.endswith('.c') or f.endswith('.h'):
            file_path = os.path.join(root, f)
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                # Remove the wrapped mock block entirely
                pattern = r'#ifdef TOOB_MOCK_TEST\s*#include "generated_boot_config\.h"\s*#endif'
                if re.search(pattern, content):
                    content = re.sub(pattern, '', content)
                    with open(file_path, 'w', encoding='utf-8') as file:
                        file.write(content)
            except Exception as e:
                pass
print("Cleanup complete!")
