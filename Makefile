all:
	cd src && $(MAKE)

tags:
	ctags -R `pwd`
	find  -name src -type d -print | xargs -I dirt -t ln -s ../tags dirt/tags
	find  -name include -type d -print | xargs -I dirt -t ln -s ../tags dirt/tags

.PHONY: clean mrproper

clean:
	cd src/ && $(MAKE) clean
	rm -rf docs/refs
