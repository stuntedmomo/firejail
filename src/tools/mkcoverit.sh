#!/bin/bash

# unpack firejail archive
ARCFIREJAIL=`ls *.tar.xz| grep firejail`
if [ "$?" -eq 0 ];
then
	echo "preparing $ARCFIREJAIL"
	DIRFIREJAIL=`basename $ARCFIREJAIL  .tar.xz`
	rm -fr $DIRFIREJAIL
	tar -xJvf $ARCFIREJAIL
	cd $DIRFIREJAIL
	./configure --prefix=/usr
	cd ..
else
	echo "Error: firejail source archive missing"
	exit 1
fi

# build
cd $DIRFIREJAIL
cov-build --dir cov-int make -j 4 extras
tar czvf myproject.tgz cov-int
