# bro_scripts
These scripts are supposed to be used with BRO Ids in order to streamline logging, add new interesting alerts and so on.

If a script ends up in this repo you know that it has been tested and are quite likely in production somewhere.

The code is an amalgamation of my own ideas and stuff I've found online and/or had help with from others. I will try to add stuff here as I go on. Hopefully some of it will find use outside of my organisation too.

As always - there are no guarantees that it will work for you but it _should_ work.

If you have any ideas, questions or just want to discuss new things to do with Bro - please feel free to contact me.

The scripts should be fairly self-explanatory but here's a quick blurb about each one.

#### filter_s0_conn.bro
This is just a quick and dirty script that cuts out 'S0 connections' from non-local hosts. This will make you lose some indicators of portscans but it will also cut down your log usage markedly. Your SIEM account manager might not like it but your budget will.

#### unusual_http_methods.bro
This little snippet will log out unusual HTTP methods such as 'DELETE', 'COPY' and 'MOVE'. HTTP methods that are so rare that they really should make your Spideysenses tingle.