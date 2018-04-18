#!/bin/sh

for i in "$@"; do
astyle -A3 -s -xn -xW -Y -p -H -U -k3 -W3 -j -c -xy -xL *.${i}
rm *.orig
done

