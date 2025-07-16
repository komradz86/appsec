#!/bin/sh

# Get venv site-packages path
DSTDIR=`python3 -c 'import sysconfig; print(sysconfig.get_path("platlib"))'`

# Clean up
rm -f $DSTDIR/lasso.*
rm -f $DSTDIR/_lasso.*

# Link
ln -s /usr/lib/python3/dist-packages/lasso.py $DSTDIR/
for SOFILE in /usr/lib/python3/dist-packages/_lasso.cpython-*.so
do
  ln -s $SOFILE $DSTDIR/
done

exit 0
