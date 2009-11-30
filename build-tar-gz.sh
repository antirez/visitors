#!/bin/sh
if [ -z $1 ]
then
	VER="current"
else
	VER=${1}
fi

make clean
rm -rf releases/visitors_${VER}
mkdir -p releases/visitors_${VER} 2> /dev/null
cp * releases/visitors_${VER}
# Better to don't compress the man page for Debian developers easy fix.
# gzip -9 releases/visitors_${VER}/visitors.1
cd releases
tar cvzf visitors-${VER}.tar.gz visitors_${VER}
cd ..
