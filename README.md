-= R&D for forcing relro and aslr on statically linked executables =-

BUILD NOTES: These tools need to be updated to work on versions of glibc that don't
use generic_start_main. This code was all designed on ubuntu 16 with libc 2.27
and GNU CC version 7.3.0.

Run 'make'

To build relros.c, and static_to_dyn.c, both of which will automatically be applied to
test.c and test2.c.

After typing make, test will be a static executable with RELRO and test2 will be a static
executable with ASLR applied.

- elfmaster

