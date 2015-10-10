PROGRAM=GRE
PROFILE=Release
DISTDIR=./dist
BUILDIR=./build
DSTROOT=$(BUILDIR)/gre.dst
PRODUCT=$(DISTDIR)/${PROGRAM}.pkg
DMGFILE=$(PROGRAM).dmg


.PHONY: all
all: dist


bin:
	mkdir -p $(DSTROOT)
	xcodebuild DSTROOT=$(DSTROOT) -configuration $(PROFILE) install


pkg: bin
	pkgbuild --root $(DSTROOT) $(PRODUCT)


dist: pkg
	mkdir -p $(DISTDIR)
	hdiutil create -volname "GRE" -layout NONE -format UDBZ -nospotlight -noanyowners -srcfolder $(DISTDIR) -ov $(DMGFILE)


.PHONY: clean distclean
clean: distclean
	xcodebuild -configuration $(PROFILE) clean
	-rm -rf $(BUILDIR)

distclean:
	-rm -rf $(DISTDIR)
	-rm -f $(DMGFILE)

