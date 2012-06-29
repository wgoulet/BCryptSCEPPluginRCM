scepplugin:
	cc -Wall -g scepplugin.c ./lib/bcrypt.a ./lib/crypt_blowfish.a -shared -o scepplugin.so

clean:
	rm -f scepplugin.so
