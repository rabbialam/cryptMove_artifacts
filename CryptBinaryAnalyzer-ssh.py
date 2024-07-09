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



# In[4]:
cfg_time_start = time.time()

file_name = "/<path_to_ssh.exe>/"
proj = angr.Project(file_name, load_options={'auto_load_libs':False},)#use_sim_procedures=True,default_analysis_mode="symbolic")

cfg = proj.analyses.CFGFast(force_smart_scan=False,force_complete_scan=True,)#function_starts=putty_stack)

print("CFG has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

cfg_time_end=time.time()
print(f"Total time for CFG generation: {cfg_time_end-cfg_time_start}")


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
    




def is_node_exists(tree,addr,reg,offset):
    for n in tree.nodes():
        if n.addr == addr and n.reg == reg and n.offset == offset:
            return True
        
    return False


# In[14]:


def tracker_check(tracker_reg,tracker_offset,reg,offset):
  

    if  tracker_reg != "rsp":
        return tracker_reg==reg
    else:
        return tracker_reg==reg and tracker_offset == offset
    


# In[15]:


#this funciton traverse a block to track a register
def block_traverse(block,graph,branch_node,tracker,offset):
    capstone_insns = block.disassembly.insns
    for ins in reversed(capstone_insns):
        
        if tracker == "rsp" and ins.mnemonic == "push":
            offset -= 8
            print(offset)
        if tracker == "rsp" and ins.mnemonic == "pop":
            offset += 8
            print(offset)
        if tracker == "rsp" and ins.mnemonic == "sub":
            op = ins.operands[0]
            if ins.reg_name(op.value.reg) == "rsp":
                #print(ins.operands[1].imm)
                offset -= ins.operands[1].imm
                #print(offset)
        if ins.mnemonic == "sub":
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
                    #print(hex(ins.address),ins.mnemonic,ins.op_str)              
                    if branch_node != None:
                        graph.add_edge(branch_node,node)
                    branch_node = node
                
                tracker = reg
                if reg == "rbp":
                    offset = disp
                if reg == "rsp":
                    offset = disp
               # if reg == "rax":
                #    return
                #if reg =="rip":
                 #   return
    return branch_node,tracker,offset
                


# In[16]:


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
        for p in cfg_pred:
            # get function transition node from fcg node
            #print("got g")
            print(hex(p.function_address))
            block_node = cfg.kb.functions[p.function_address].get_node(p.addr)
            pred_list.append(block_node)
    for src in pred_list:
        if src not in visited_set:
            
            multi_path_discovery(graph,branch_node,src,cfg,tracker,offset,visited_set)


# In[17]:

backtracking_time_start = time.time()
import sys
sys.setrecursionlimit(1000)
graph= nx.DiGraph()
sec_main = cfg.kb.functions[0x1400536A0].get_node(0x1400536A0)

tracker = "rcx"
branch_node = operand_node(0x1400536A0,tracker,0,None)
visited_set = set()
multi_path_discovery(graph,None,sec_main,cfg,tracker,0,visited_set)
backtracking_time_end = time.time()

print(f"total time for backtracking: {backtracking_time_end-backtracking_time_start}")


from networkx.drawing.nx_pydot import graphviz_layout
pos = graphviz_layout(graph, prog="dot")
plot_common(graph,"ssh_tracker.png")


end = time.time()
print("time diff time",end-start)

