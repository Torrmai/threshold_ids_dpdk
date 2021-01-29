START_TIME=$(date -u +%s)
./build/senior_backend -l 1-3 -- -T 5 -V 1
END_TIME=$(date -u +%s)
echo "It takes $(($END_TIME - $START_TIME)) seconds to complete this task..."