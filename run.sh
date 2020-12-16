#!/bin/bash
echo -n "Please enter time peroid in second(integer): "
read tim
echo -n "Do you want to verbose(Y/n): "
read ver
echo -n "Usage limit in bit: "
read lim
# toggle verbose mode 
if [ "$ver" == "Y" ]; then 
	./build/senior_backend -l 1-3 -- -T "$tim" -V 1 -L "$lim"
elif [ "$ver" == "y" ]; then
	./build/senior_backend -l 1-3 -- -T "$tim" -V 1 -L "$lim"
else
	./build/senior_backend -l 1-3 -- -T "$tim" -L "$lim"
fi
