#!/usr/bin/env python
# coding: utf-8

# In[19]:


import angr
import time
from capstone import *
from capstone.arm64 import *
ARM64_OP_REG = 1
ARM64_OP_MEM = 3
start = time.time()
print("current time",start)


# In[20]:


#file_name = "/Users/rabby/Downloads/curl-8.3.0_2-win64-mingw/bin/curl.exe"
#argument = ['curl', 'https://learn.microsoft.com/en-us/azure/iot-central/core/howto-integrate-with-devops']


# In[21]:


#.    140040270->0x140093D20  
#        0x140096A00 ->0x14004EEC0
#      14000C3C0->0x140097CF0


# In[22]:


import logging


# In[24]:


def show_transition_graph(function_addr):
    tran_graph = cfg.kb.functions[function_addr].graph
    for n in tran_graph.nodes():
        print(n)


# In[25]:


def show_block(addr):
    block = proj.factory.block(addr)
    capstone_insns = block.disassembly.insns
    for ins in capstone_insns:
        print(ins)


# In[28]:


class Delay_loader_helper:
    __slots__ = ("_descriptor_addr", "_project")
    def __init__(self,descriptor_addr,project):
        self._descriptor_addr = descriptor_addr
        self._project = project
        
    def find_string_with_unknown_size(self,project, start_address):
        string_content = b""
        current_address = start_address

    # Read memory until a null byte (end of string) is encountered
        while True:
            byte_value = project.loader.memory.load(current_address, 1)
            if byte_value == b'\x00':
                break

            string_content += byte_value
            current_address += 1

    # Convert the string content to a Python string
        string_value = string_content.decode('utf-8')  # Adjust the encoding if necessary

        return string_value
    def _read_memory_and_get_address_from_offset(self,addr):
        base = self._project.loader.main_object.min_addr
        data_content = self._project.loader.memory.load(addr, 4)
        offset = int.from_bytes(data_content,"little")
        if(offset ==0):
            return 0
        address = base+offset
        return address
    def _get_discryptor_function_map(self):
        add_table_offset = self._read_memory_and_get_address_from_offset(self._descriptor_addr+12)
        print(f"Address table address: {hex(add_table_offset)}")

        name_table_offset = self._read_memory_and_get_address_from_offset(self._descriptor_addr+16)
        print(f"Name table address: {hex(name_table_offset)}")
        
        function_map = {}
        x=0
        while True:
            string_addr = self._read_memory_and_get_address_from_offset(name_table_offset+(x*8))
            if(string_addr==0):
                break;
                #print(int.from_bytes(dd,"little"))
            api = self.find_string_with_unknown_size(proj,string_addr+2)
    
            #print(f"API name {api} and address {hex(add_table_offset+(x*8))}")
            function_map[api]=add_table_offset+(x*8)
            x+=1
        return function_map
        
    def delay_load(self):
        
        dll_name_offset = self._read_memory_and_get_address_from_offset(self._descriptor_addr+4)
       # print(hex(dll_name_offset))
        dll_name =  self.find_string_with_unknown_size(self._project,dll_name_offset)
        print(f"Delay loading {dll_name}......")
        
        function_map = self._get_discryptor_function_map()
        self._project.loader.dynamic_load(dll_name)
        loaded_dll = proj.loader.find_object(dll_name)
        if loaded_dll == None:
            print(f"File {dll_name} note found")
            return
        # updating funciton pointers in discriptor table from loaded libary exported symbols
        for func in function_map.keys():
            #print(func)
            sym = loaded_dll.get_symbol(func)
            if sym == None:
                print(f"Function pointer not found for function {func}")
                continue
            
            proj.loader.memory.store(function_map[func],sym.rebased_addr.to_bytes(8, byteorder='little'))
            print(f"API name {func} address in dll {hex(sym.rebased_addr)}")


# In[29]:


import pefile

def find_delay_import_descriptor(pe):
    # Check if the binary has a delay import directory
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        delay_import_descriptor = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']]
        return delay_import_descriptor
    else:
        return None

#binary_path = "your_binary.exe"
#logging.getLogger('cle').setLevel('DEBUG')

def main(file_name):
	proj = angr.Project(file_name, load_options={'auto_load_libs':False},)#'force_load_libs':lib_list,'skip_libs':skip_libs_list},)#use_sim_procedures=True,default_analysis_mode="symbolic")

	print("Loaded objects....")
	for x in proj.loader.all_objects:
		print(x)

	pe = pefile.PE(file_name)

	delay_import_descriptor = find_delay_import_descriptor(pe)

	if delay_import_descriptor:
		base = proj.loader.main_object.min_addr
		table_start = delay_import_descriptor.get_file_offset()+base
		data_content = proj.loader.memory.load(table_start, 4)
		offset = int.from_bytes(data_content,"little")
		if(offset ==0):
			print("no descriptor found")
		address = base+offset
    
		size = delay_import_descriptor.Size -0x20 # for printing the first address
		while size>0:
			print(hex(address))
        
			delay_loader = Delay_loader_helper(address,proj)
			delay_loader.delay_load()
        
			address += 0x20
			size -=0x20
    
		print(f"offset {hex(table_start)} Size {hex(size)}")
	else:
		print("No Delay Import Descriptor found.")


# In[30]:


	print("Loaded objects....")
	for x in proj.loader.all_objects:
		print(x)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <file_path>")
        sys.exit(1)
    main(sys.argv[1])
# In[ ]:

#plot_cg(proj.kb, "%s_callgraph_verbose" % name, format="png", verbose=True)


end = time.time()
print("time diff time",end-start)

