sleep_time=$1

while true; do
	pkill ubbdd
	sleep ${sleep_time}
done
