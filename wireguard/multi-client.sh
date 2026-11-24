#export KEYLEASE=500
#export LEASE=250 

n=3

./client-wg-req-mon.sh blackbox wgservice
sleep $n
./client-wg-req-mon.sh whitebox wgservice
sleep $n
./client-wg-req-mon.sh greenbox wgservice
sleep $n
./client-wg-req-mon.sh redbox wgservice
sleep $n
./client-wg-req-mon.sh bluebox wgservice
sleep $n
./client-wg-req-mon.sh cuddly wgservice
sleep $n
./client-wg-req-mon.sh sweetly wgservice
sleep $n
./client-wg-req-mon.sh deadly wgservice
