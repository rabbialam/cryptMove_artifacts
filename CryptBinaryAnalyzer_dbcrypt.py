#!/usr/bin/env python
# coding: utf-8

# In[1]:


import angr
from angrutils import *
import time
from capstone import *
from capstone.arm64 import *
ARM64_OP_REG = 1
ARM64_OP_MEM = 3
start = time.time()
print("current time",start)


# In[2]:


import json
import networkx as nx
import matplotlib.pyplot as plt  # Optional, for visualization

class StackNode:
    __slots__ = ("nodes", "name", "count","offset")

    def __init__(self, name, count):
        if name != "root":
            sp = name.split("!")
            self.offset = int(sp[1])
            self.name = sp[0]
        else :
            self.name = 0
            self.offset=0
        self.count = count
        self.nodes = {}

    def get_as_addr(self):
        return int(self.name)

    def __str__(self):
        if self.name == "root":
            return self.name 
        return f"{self.name}!{hex(self.offset)}"


# In[3]:


def build_tree(graph, parent_node, stack_node):
    node_id = hex(id(stack_node))
    graph.add_node(stack_node)
    if parent_node != None:
        graph.add_edge(parent_node,stack_node)
    print(str(stack_node))
    for child_name, child_node in stack_node.nodes.items():
        #child_node_id = hex(id(child_node))
        #graph.add_node(child_node, label=str(child_node))
        #graph.add_edge(stack_node, child_node)
        build_tree(graph, stack_node,child_node)


# In[4]:


def parse_json(json_obj):
    stack_node = StackNode(json_obj.get("name", ""),json_obj.get("count", ""))
    for key, value in json_obj.items():
         if isinstance(value, dict):
             stack_node.nodes[key]=parse_json(value)
    return stack_node


# In[5]:


from networkx.drawing.nx_pydot import graphviz_layout

json_file_path = '<path_to_output_of_stackRecorder.js>'

# Load JSON data from file
with open(json_file_path, 'r') as file:
    json_data = json.load(file)
stack_root = parse_json(json_data)    
# Create a directed graph
dynamic_graph = nx.DiGraph()

# Build the tree in the graph
build_tree(dynamic_graph, None, stack_root)
#plot_common(graph,"putty_stack.png")
# Draw the graph (optional, requires matplotlib)
pos = graphviz_layout(dynamic_graph, prog="dot")

nx.draw(dynamic_graph, pos, with_labels=True, font_weight='bold', node_size=700, node_color='skyblue', font_size=8)
plt.show()



dbclient = "path_to_db_client_exe"
proj = angr.Project(dbclient, load_options={'auto_load_libs':False},)#use_sim_procedures=True,default_analysis_mode="symbolic")
#proj.loader.dynamic_load(ssh2Core)
cfg_time_start = time.time()
cfg = proj.analyses.CFGFast(force_smart_scan=False,force_complete_scan=True,)#function_starts=putty_stack)


# In[9]:


def get_call_block(ret_addr):
    cfg_node = cfg.get_any_node(ret_addr)
    func = cfg.kb.functions[cfg_node.function_address]
    trans_graph = func.graph
    #print("previous locations...")
    low = cfg_node.function_address
    for node in trans_graph.nodes():
        if node.addr > low and node.addr<ret_addr:
            low = node.addr
    #print(f"call bolck {hex(low)}")        
    return cfg.get_any_node(low)


# In[10]:


def get_base_address(module_name):
    obj = proj.loader.find_object(module_name)
    print(obj)
    if obj:
        return obj.min_addr
    else:
        print("module not found")
    


# In[11]:


#base_address = proj.loader.main_object.min_addr
def resolveIndirectCalls():
    for dNode in dynamic_graph.nodes():
        if dNode.name ==0:
            continue
        base_address=get_base_address(dNode.name)
        print(hex(dNode.offset))
        if dNode.name == "KERNEL32" or dNode.name == "ntdll" or dNode.name == "ucrtbase" or dNode.name == "cygwin1":
            continue
        #print(hex(dNode.offset+base_address))
        cfgNode = cfg.get_any_node(dNode.offset+base_address)
        #print(f"cfg node {cfgNode}")
        print(f"nodes function address {hex(cfgNode.function_address)}")
        func_node = cfg.get_any_node(cfgNode.function_address)
        for node in dynamic_graph.successors(dNode):
            if node.name == "KERNEL32" or node.name == "ntdll" or node.name == "ucrtbase" or node.name =="cygwin1":
                continue
            rbase_address=get_base_address(node.name)
            return_address = rbase_address + node.offset
            print(f"call return address {hex(return_address)} node name {node.name}")
            call_block=get_call_block(return_address)
            #print(f"caller node {call_block} clallee node {cfgNode}")
            #print(cfg.graph.has_edge(call_block,func_node))
            if cfg.graph.has_edge(call_block,func_node) == False:
                print("Function pointer detected, adding call location")
                print(f"caller node {call_block} clallee node {func_node}")
                cfg.graph.add_edge(call_block,func_node)
            #print(hex(previous_instruction))


resolveIndirectCalls()
cfg_time_end = time.time()
cfg_time = cfg_time_end-cfg_time_start



class operand_node:
    __slots__ = ("addr","reg","offset","capstone_ins")
    
    def __init__(self,addr,reg,offset,capstone_ins):
        self.addr=addr
        self.reg=reg
        self.offset = offset
        self.capstone_ins = capstone_ins
    
    def pp(self):
        return hex(self.capstone_ins.address) + "\t"+self.capstone_ins.mnemonic+" "+self.capstone_ins.op_str 
    
    def __str__(self):
        return hex(self.capstone_ins.address) + "\t"+self.capstone_ins.mnemonic+" "+self.capstone_ins.op_str 
    


# In[14]:


def is_node_exists(tree,addr,reg,offset):
    for n in tree.nodes():
        if n.addr == addr and n.reg == reg and n.offset == offset:
            return True
        
    return False


# In[15]:


def tracker_check(tracker_reg,tracker_offset,reg,offset):
  

    if  tracker_reg != "rsp":
        if offset!=0:
           return tracker_reg==reg and tracker_offset == offset 
        return tracker_reg==reg
    else:
        #print(f"RSP register and offset {offset} trackeroffset {tracker_offset}")
        return tracker_reg==reg and tracker_offset == offset
    


# In[16]:


#this funciton traverse a block to track a register
def block_traverse(block,graph,branch_node,tracker,offset):
    capstone_insns = block.disassembly.insns
    for ins in reversed(capstone_insns):
        
        if tracker == "rsp" and ins.mnemonic == "push":
            offset -= 8
            #print(hex(offset))
        if tracker == "rsp" and ins.mnemonic == "pop":
            offset += 8
            #print(offset)
        if tracker == "rsp" and ins.mnemonic == "sub":
            op = ins.operands[0]
            if ins.reg_name(op.value.reg) == "rsp":
                #print(ins.operands[1].imm)
                offset -= ins.operands[1].imm
                #print(offset)
        if ins.mnemonic == "sub" or ins.mnemonic == "add":
            op = ins.operands[0]
            if ins.reg_name(op.value.reg) == tracker:
                node = operand_node(ins.address,tracker,0,ins)
                graph.add_node(node)
                print(hex(ins.address),ins.mnemonic,ins.op_str)              
                if branch_node != None:
                    graph.add_edge(branch_node,node)
                branch_node = node
        
        if  "mov" in ins.mnemonic  or ins.mnemonic == "lea":
            reg=""
            disp =0
            if ins.address == 0x14000f601:
                print("initial pointer address->>>>>>>>>>>>>>>>")
            op = ins.operands[0]
            if(op.type == ARM64_OP_REG):
                reg=ins.reg_name(op.value.reg)
            if(op.type == ARM64_OP_MEM):
                if op.value.mem.base != 0:
                    reg=ins.reg_name(op.value.mem.base)
                if op.value.mem.disp != 0:
                    disp= op.value.mem.disp

            if tracker_check(tracker,offset,reg,disp):
                op = ins.operands[1]
                if(op.type == ARM64_OP_REG):
                    reg=ins.reg_name(op.value.reg)
                if(op.type == ARM64_OP_MEM):
                    if op.value.mem.base != 0:
                        reg=ins.reg_name(op.value.mem.base)
                    disp= op.value.mem.disp
                
                if is_node_exists(graph,ins.address,reg,disp) is False:
                    node = operand_node(ins.address,reg,disp,ins)
                    graph.add_node(node)
                    print(hex(ins.address),ins.mnemonic,ins.op_str)              
                    if branch_node != None:
                        graph.add_edge(branch_node,node)
                    branch_node = node
                
                tracker = reg
                if reg == "rbp":
                    offset = disp
                if reg == "rsp":
                    offset = disp
                if reg == "rax":
                    return branch_node,tracker,offset
                if reg =="rip":
                    return branch_node,tracker,offset
    return branch_node,tracker,offset
                


# In[17]:


# this function will traverse the function transition graph first, then it will follow out of the function and move
#into the cfg graph to get out of the function.

#in here node is a blocknode object from a function transition graph block node
def multi_path_discovery(graph,branch_node,node,cfg,tracker,offset,visited_set):
    block = proj.factory.block(node.addr)
    visited_set.add(node)

    branch_node,tracker,offset = block_traverse(block,graph,branch_node,tracker,offset)
    # 
    #print(f"Tracker {tracker} Branch Node {branch_node}")
    try:
        pred_list = node.predecessors()
    except Exception:
        print("exception")
        return
    if len(pred_list) == 0:
        cfg_node = cfg.get_any_node(node.addr)
        cfg_pred = cfg.graph.predecessors(cfg_node)
        #if len(cfg_pred) ==0:
         #   return
        if tracker == 'rsp':
                offset -=8
                #print(f"offset value in caller function {hex(offset)}")
        for p in cfg_pred:
            # get function transition node from fcg node
            #print("got g")
            #print(hex(p.function_address))
            block_node = cfg.kb.functions[p.function_address].get_node(p.addr)
            pred_list.append(block_node)
            
           
    for src in pred_list:
        if src not in visited_set:            
            multi_path_discovery(graph,branch_node,src,cfg,tracker,offset,visited_set)


# In[18]:


import sys
sys.setrecursionlimit(1000)
graph= nx.DiGraph()
sec_main = cfg.kb.functions[0x100419080].get_node(0x100419080)

tracker = "rcx"
branch_node = operand_node(0x100419080,tracker,0,None)
visited_set = set()
path_gen_time_start = time.time()
multi_path_discovery(graph,None,sec_main,cfg,tracker,0,visited_set)
path_gen_time_end = time.time()
print(f"CFG gen time {cfg_time} path generation time {path_gen_time_end-path_gen_time_start}")


# In[19]:


for function in cfg.kb.functions.values():
    print(function.name)


# In[20]:


from networkx.drawing.nx_pydot import graphviz_layout
pos = graphviz_layout(graph, prog="dot")
plot_common(graph,"dbclient_chacha_poly.png")


# In[24]:




end = time.time()
print("time diff time",end-start)


# In[29]:


print(f"CFG gen time {cfg_time} path generation time {path_gen_time_end-path_gen_time_start}")
print("CFG has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

