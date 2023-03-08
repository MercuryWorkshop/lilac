privesc.sh: allassets allbinaries privesc.sh.pre
	cpp -P -E -traditional-cpp -o privesc.sh < privesc.sh.pre

allbinaries: policy/patchpolicy.b64
allassets: assets/pdf.pdf.b64 assets/ppd.ppd.b64

%.b64: %
	bzip2 -9c $< | base64 -w 100 > $@

policy/patchpolicy: policy/patchpolicy.cc
	make -C policy

assets/%.b64: assets/%
	bzip2 -9c $< | base64 -w 100 > $@

clean:
	rm -f assets/*.b64 privesc.sh policy/patchpolicy policy/patchpolicy.b64
