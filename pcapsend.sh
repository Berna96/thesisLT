#!bin/bash

#configuration for running rsync daemon

cat << _EOF_
	lock file = /var/run/rsync.lock
	log file = /var/log/rsyncd.log
	pid file = /var/run/rsyncd.pid
[documents]
	path = /home/berna/Documents
	comment = The documents folder of Berna
	uid = berna
	gid = berna
	read only = no
	list = yes
	auth users = rsyncclient
	secrets file = /etc/rsyncd.secrets
	hosts allow = 192.168.1.0/255.255.255.0
_EOF_
<< rsyncd.conf

cat << _EOF_
  	rsyncclient:passWord
	berna:PassWord
	backup:Password
	user:password
_EOF_
<< rsyncd.secrets

sudo chmod 600 /etc/rsyncd.secrets
sudo rsync --daemon

