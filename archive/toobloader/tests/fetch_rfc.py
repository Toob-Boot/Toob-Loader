import urllib.request
import binascii

url = "https://www.rfc-editor.org/rfc/rfc7539.txt"
response = urllib.request.urlopen(url)
data = response.read().decode('utf-8')

# Search for the exact ciphertext block of Section 2.3.2
lines = data.split('\n')
in_ciphertext = False
hex_bytes = []
for line in lines:
    if "Ciphertext:" in line:
        in_ciphertext = True
        continue
    if in_ciphertext:
        if line.strip() == "":
            if len(hex_bytes) > 0:
                break
            continue
        # Extract the hex part, which is from character 8 to 55 typically
        parts = line.strip().split()
        if len(parts) > 1 and parts[0].isdigit():
            # This is a hex line like: 000  6e 2e 35 ...
            for p in parts[1:]:
                if len(p) == 2 and all(c in "0123456789abcdef" for c in p):
                    hex_bytes.append(p)
                else:
                    break

rfc_bytes = bytes.fromhex("".join(hex_bytes))
print(f"Extracted {len(rfc_bytes)} bytes from RFC 7539:")
print(binascii.hexlify(rfc_bytes).decode('ascii'))
