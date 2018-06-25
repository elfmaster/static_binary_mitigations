all:
	gcc -g relros.c libelfmaster_pre_beta/libelfmaster.a -o relros
	gcc -g static_to_dyn.c -o static_to_dyn
	gcc -static test.c -o test
	gcc -nostdlib -c -fPIC test2.c -o test2.o
	gcc -nostdlib test2.o dietlibc_fpic/dietlibc.a -o test2
	./relros test
	./static_to_dyn test2
	@echo 'full RELRO applied to test binary'
	@echo 'ASLR requirements applied to test2 binary'
clean:
	rm -f *.o relros static_to_dyn test test2
