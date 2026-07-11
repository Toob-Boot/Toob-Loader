import re
import os

def main():
    boot_state_path = "toobloader/core/boot_state.c"
    output_path = "docs/state_diagram.mermaid"

    if not os.path.exists(boot_state_path):
        print(f"Error: {boot_state_path} not found")
        return

    with open(boot_state_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Match tables using regex (matching up to the closing definition '};')
    table_match = re.search(r"static\s+const\s+intent_row_t\s+INTENT_TABLE\[\]\s*=\s*\{(.*?)\};", content, re.DOTALL)
    if not table_match:
        print("Error: Could not find INTENT_TABLE in boot_state.c")
        return

    rows_raw = table_match.group(1).strip().split("\n")
    transitions = []

    for row in rows_raw:
        row = row.strip()
        if not row or row.startswith("//") or row.startswith("/*"):
            continue
        # Extract fields: { CUR, EV, NEXT, ACT }
        m = re.match(r"\{\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*\}", row)
        if m:
            cur, ev, next_state, act = m.groups()
            transitions.append((cur, ev, next_state, act))

    # Generate Mermaid Content
    lines = ["stateDiagram-v2"]
    for cur, ev, next_state, act in transitions:
        # Simplify labels for display
        cur_clean = cur.replace("WAL_INTENT_", "")
        next_clean = next_state.replace("WAL_INTENT_", "")
        ev_clean = ev.replace("EV_", "")
        act_clean = act.replace("ACT_", "")
        
        lines.append(f"    {cur_clean} --> {next_clean} : {ev_clean} ({act_clean})")

    mermaid_content = "\n".join(lines) + "\n"

    # Write to file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(mermaid_content)

    print(f"Successfully generated {output_path}")

if __name__ == "__main__":
    main()
