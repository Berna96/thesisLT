#!/bin/bash

#to execute at the beginning

sendfile(){
	echo "Sending files..."
	PART=$(($PART+1))
	MOD=$((($PART+1)%2))
	PATHONE=pcapfiles/$MOD/*.pcap
	PATHTWO=$HO/pcapfiles/partition$PART/
	rsync -a --rsync-path="mkdir -p pcapfiles/partition$PART/ && rsync" pcapfiles/$MOD/ $HOSTDEST/pcapfiles/partition$PART/
	#rsync pcapfiles/$MOD/*.pcap $HOSTDEST/pcapfiles/partition$PART/
	if [ "$?" -eq 0 ]; then
		echo "Transfering file successfully"
	else
		echo "Error sending files: Compress"
		tar -czvf partition$PART.tar.gz pcapfiles/$MOD/ 
		if [ "$?" -ne 0 ]; then
			echo "Failed to compress file: Recover pcapfiles/$MOD/ manually before time expires"
		fi
	fi
}

exitfunct(){
	echo "Exiting program..."
	MOD=0
	PART=0
	break
	exit 0
}

usage(){
	echo "$0 [user@]host dest/folder"
	exit 1
}

if [ "$#" -ne 2 ]; then
	usage
fi

#echo $$
PID=$$
#echo $PID

PART=0
MOD=0
HOST=$1
DESTFOLD=$2
HOSTDEST="$HOST:$DESTFOLD"
trap "sendfile" USR1
trap "exitfunct" INT

rm ~/.ssh/id_rsa*
echo "Copying test file.."
rsync pcapfiles/.test/testfile.txt $HOSTDEST && \
echo "When asking, don't insert nothing and press Enter" && \
echo "" | ssh-keygen && \
ssh-copy-id  $HOST && \
echo "Copying test file.." && \
rsync portlist.conf  $HOSTDEST/pcapfiles/ && \
#-a --rsync-path="""mkdir -p $HOMEDEST/pcapfiles/ && rsync"
sudo ./pcapevolve $PID &
#echo "$?"
if [ "$?" -ne 0 ]; then
	echo "Something failed... Exiting"
	exit 3
fi

while true; do	
	sleep 5
done


