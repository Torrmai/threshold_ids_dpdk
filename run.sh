#!/bin/bash
echo -n "Please enter time peroid in second(integer): "
read tim
echo -n "Do you want to verbose(Y/n): "
read ver
# toggle verbose mode 
if [ "$ver" == "Y" ]; then 
	./build/senior_backend -l 1-3 -- -T "$tim" -V 1
elif [ "$ver" == "y" ]; then
	./build/senior_backend -l 1-3 -- -T "$tim" -V 1
else
	./build/senior_backend -l 1-3 -- -T "$tim"
fi
