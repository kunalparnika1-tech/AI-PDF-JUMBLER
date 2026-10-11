"""Secure Device Disposal — simulation-only planning and orchestration tool.

This package implements a NON-DESTRUCTIVE prototype for planning and reviewing
authorized device-retirement operations. It performs NO disk wiping, NO
bootloader modification, and NO partition deletion. Every "disposal" action is
simulated: the tool records what a vendor-approved procedure *would* do and
requires explicit human authorization before a request is even locked.

See docs/LIMITATIONS.md for the full statement of what this tool does and does
not do.
"""

__version__ = "0.1.0"

# Hard safety switch. This prototype ships in simulation mode and has no code
# path that performs destructive operations. The flag exists so that any future
# contributor who tries to add one has to confront an explicit, reviewed gate
# rather than silently flipping behaviour.
SIMULATION_ONLY = True
