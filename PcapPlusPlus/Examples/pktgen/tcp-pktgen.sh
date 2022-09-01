DEST="10.10.10.2"
CLIENT=0
SERVER=0
DURATION=100
CONG=cubic
# To test the limits make sure to do the following at the sender/receiver NICs
# Change MTU to 100
# use ethtool -K <interface>rx off tx off gro off sg off
# The above will make sure sender/receiver are generating 100B packets without
usage() { echo "Usage: $0 -s <number of senders> -r <number of receivers" 1>&2; exit 1; }

while getopts "r:s:a:" arg; do
    case $arg in
        h) usage ;;
        r) SERVER=$OPTARG;;
        s) CLIENT=$OPTARG;;
        a) CONG=$OPTARG;;
        *) usage ;;
    esac
done

PORT=5201
while [ $CLIENT -ge 1 ]
do
    iperf3 -c $DEST -p $PORT -t $DURATION -C $CONG | grep sender | tail &
    ((PORT++))
    ((CLIENT--))
done

PORT=5201
while [[ $SERVER -ge 1 ]]
do
    iperf3 -s -p $PORT&
    ((PORT++))
    ((SERVER--))
done
