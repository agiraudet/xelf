
import sys

def format_as_c_array(binary_data):
    # formatted_code = [f'0x{byte:02x}, ' for byte in binary_data]
    formatted_code = [input_string[i:i+2] for i in range(0, len(binary_data), 2)]
    
    return f'const char assemblyCode[] = {{\n    {"".join(formatted_code)}\n}};'

if __name__ == "__main__":
    try:
        binary_data = sys.stdin.buffer.read()
        formatted_c_array = format_as_c_array(binary_data)
        print(formatted_c_array)
    except Exception as e:
        print(f"Error: {e}")
