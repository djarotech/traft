> systemctl start postgresql
> msfdb init
> -msfconsole

msf > db_rebuild_cache
msf > load msgrpc [Pass=password]
msf > msfrpcd -P password -S


