# To do: put envars. for build version, build time, and default settings# To do: put envars. for build version, build time, and default settings# To do: put envars. for build version, build time, and default settings
build:
	go build

test: clean
	go install

	alvis setup -out tmp/master.priv

	cd tmp/ && time alvis encrypt -msk master.priv -data-dir patients/ -out-dir enc_patients

	cd tmp/ && alvis extract keyword -msk master.priv -words words.txt -out-dir keys

	cd tmp/ && alvis extract frequency -msk master.priv -out freq.sk

	cd tmp/ && time alvis decrypt -key-dir keys/ -freq-key freq.sk -data-dir enc_patients/ -out-dir dec_patients

clean:
	rm -f alvis
	rm -f tmp/master.priv
	rm -f tmp/freq.sk
	rm -rf tmp/dec_patients/
	rm -rf tmp/keys/
	rm -rf tmp/enc_patients/

stats:
	go install
	cd tmp/ && alvis stats -data-dir patients/

install:
	go install

.PHONY: build test clean install stats
