import json
import angr
import os
import capstone


# Open and read the JSON file
with open('database_full.json', 'r') as json_file:
    json_data = json_file.read()

try:
    parsed_data = json.loads(json_data)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON: {e}")
    
def find_encryption_function(proj):
    
    cfg = proj.analyses.CFGFast(force_smart_scan=False,force_complete_scan=True,)
    sBox_loc = set()
    const_name_addr = {}
    for item in parsed_data:
        name = item.get('name', 'N/A')
        pattern = bytes.fromhex(item.get('hexBytes', 'N/A'))
    
        results = proj.loader.memory.find(pattern)
        
        for addr in results:
            sBox_loc.add(addr)
            print(f"{name} found at address: 0x{addr:08x}")
            const_name_addr[addr]=name
    sBox_user_fun = set()
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    print(f"Var len{len(sBox_loc)}")
    for n in cfg.kb.functions:
        #print(hex(n))
        func =cfg.kb.functions.get_by_addr(n)
        
        for block in func.blocks:
            try:
                # Disassemble the block's code
                instructions = block.disassembly.insns
            except Exception as e:
                continue  # Skip blocks that cannot be disassembled
            
            # Check each instruction for the aesenc operation
            for instruction in instructions:
                if 'aesenc' in instruction.mnemonic:
                    # Save the function's address and name (if available)
                    print("aesenc found")
                    sBox_user_fun.add(n)
                    break  # Found aesenc, no need to check more blocks in this function
            

        if func:
            const = None
            try:
                const = func.code_constants
            except Exception:
                #print(f"problem in {func}")
                continue
            for x in const:
                if x in sBox_loc:
                    #print(f"Crypt function 0x{n:08x} constant is {const_name_addr[x]}")
                    sBox_user_fun.add(n)
    return sBox_user_fun

def main(file_path):
    proj = angr.Project(file_path, load_options={'auto_load_libs':False})
    crypt_func_list = find_encryption_function(proj)
    base_address = proj.loader.main_object.min_addr
    base_name = os.path.basename(file_path)
    file_name_without_extension, extension = os.path.splitext(base_name)
    print(f"Encryption funciton for {file_name_without_extension}")
    output_file_path = file_name_without_extension
    with open(output_file_path, 'w') as file:
        for func in crypt_func_list:
            # Calculate the offset and create the formatted string
            offset = func - base_address
            formatted_string = f"{file_name_without_extension}+{hex(offset)}"
            
            # Write the formatted string to the file
            file.write(formatted_string + '\n')  # Add a newline to separate entries
            
            # Also print the string to the console
            print(formatted_string)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <file_path>")
        sys.exit(1)
    main(sys.argv[1])