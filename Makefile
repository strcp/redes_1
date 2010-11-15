all:
	cd src && $(MAKE)

.PHONY: clean mrproper

clean:
	cd src/ && $(MAKE) clean
	rm -rf docs/refs

pkgtest:
	cd src && $(MAKE) pkgtest
