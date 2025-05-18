#!/usr/bin/env python3

import angr
import sys

def main():
    project = angr.Project('./chal', auto_load_libs=False)

    # Allocate 8 symbolic bytes for the input
    input_len = 8
    input_addr = 0x404000  # Arbitrary writable memory address
    state = project.factory.entry_state()

    # Create symbolic variables and store them in memory
    for i in range(input_len):
        sym_byte = state.solver.BVS(f'input_{i}', 8)
        state.memory.store(input_addr + i, sym_byte)
        # Constrain input to printable characters (excluding newline)
        state.solver.add(sym_byte >= 0x20)
        state.solver.add(sym_byte <= 0x7e)

    # Store null terminator to simulate stripped newline in fgets
    state.memory.store(input_addr + input_len, state.solver.BVV(0, 8))

    # Overwrite return address of fgets so input goes where main expects
    state.globals['input_addr'] = input_addr
    state.regs.rdi = input_addr  # input pointer to gate(input)

    # Call gate function directly
    gate_func = project.loader.find_symbol('gate').rebased_addr
    simgr = project.factory.simgr(state)
    simgr.explore(find=gate_func + 100)  # explore a bit past gate()

    for found in simgr.found:
        result = b''
        for i in range(input_len):
            c = found.solver.eval(found.memory.load(input_addr + i, 1), cast_to=bytes)
            result += c
        sys.stdout.buffer.write(result + b'\n')
        return

    print("No solution found.")

if __name__ == '__main__':
    main()
