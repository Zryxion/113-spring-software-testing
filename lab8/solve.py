#!/usr/bin/env python3

import angr
import claripy
import sys

def main(): 
    project = angr.Project('./chal', auto_load_libs=False)

    input_len = 8
    input_chars = [claripy.BVS(f'input_{i}', 8) for i in range(input_len)]
    input_expr = claripy.Concat(*input_chars)

    state = project.factory.full_init_state(
        args=['./chal'],
        stdin=input_expr
    )

    for char in input_chars:
        state.solver.add(char >= 0x20)
        state.solver.add(char <= 0x7e)

    simgr = project.factory.simulation_manager(state)

    def is_successful(state):
        return b'Correct! The flag is:' in state.posix.dumps(1)

    # Explore paths
    simgr.explore(find=is_successful)

    if simgr.found:
        found = simgr.found[0]
        # Extract the concrete value of the symbolic input
        solution = found.solver.eval(input_expr, cast_to=bytes)
        sys.stdout.buffer.write(solution + b'\n')
    else:
        print("No solution found.")

if __name__ == '__main__':
    main()
