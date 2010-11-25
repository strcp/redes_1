all:
	cd src && $(MAKE)

doc:
	doxygen

install: all
	cp -r src/disturber /usr/sbin
	cp -r docs/disturber.7.gz /usr/share/man/man7

uninstall:
	rm -rf /usr/sbin/disturber
	rm -rf /usr/share/man/man7/disturber.7.gz

tags:
	ctags -R `pwd`
	find  -name src -type d -print | xargs -I dirt -t ln -s ../tags dirt/tags
	find  -name include -type d -print | xargs -I dirt -t ln -s ../tags dirt/tags

.PHONY: clean mrproper

clean:
	cd src/ && $(MAKE) clean
	rm -rf docs/refs
