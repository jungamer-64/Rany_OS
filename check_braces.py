import sys

def check_braces(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error opening file: {e}")
        return

    stack = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        # Simple parser avoiding regex complexity; handles // comments
        # Does NOT handle /* */ or strings, but usually good enough for code structure errors
        
        content = line
        if "//" in content:
            content = content.split("//")[0]
            
        for char in content:
            if char == '{':
                stack.append(line_num)
            elif char == '}':
                if not stack:
                    print(f"Error: Unexpected closing brace at line {line_num}")
                    return
                stack.pop()

    if stack:
        print(f"Error: Unclosed brace(s). Total open: {len(stack)}")
        print(f"Last unclosed block started at line {stack[-1]}")
        # Print context
        print(f"Context: {lines[stack[-1]-1].strip()}")
    else:
        print("Braces appear balanced.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_braces.py <filename>")
    else:
        check_braces(sys.argv[1])
