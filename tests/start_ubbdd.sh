timeout=$1

while true; do
	timeout ${timeout} ./ubbdd/ubbdd
	sleep 1
done
