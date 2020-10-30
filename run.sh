#!/bin/bash
echo "Please enter time peroid in second(integer) [ENTER]: "
read test 
./build/senior_backend -l 1-3 -- -T "$test" "-V 1"
