timeout=$1
valgrind=$2

while true; do
	if [ $valgrind -eq 1 ]; then
		valgrind --leak-check=full timeout ${timeout} ./ubbdd/ubbdd
	else
		taskset -c 1 timeout ${timeout} ./ubbdd/ubbdd
	fi
	sleep 1
done
