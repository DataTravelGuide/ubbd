timeout=$1
valgrind=$2
downtime=$3

while true; do
	if [ $valgrind -eq 1 ]; then
		valgrind --leak-check=full timeout ${timeout} ./ubbdd/ubbdd
	else
		timeout ${timeout} ./ubbdd/ubbdd
	fi
	sleep ${downtime}
done
