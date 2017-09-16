#
# This Bro filter excludes S0 connections from non-local IP's to be written
# down into the conn.log file in order to save on disk and Splunk usage.
#
# Written by Michael Eriksson, Sophos 2017-07-17
#
#

module LogFilter;

event bro_init()
{
        Log::remove_default_filter(Conn::LOG);
        Log::add_filter(Conn::LOG, [$name = "conn-filter-external-S0",
                                    $pred(rec: Conn::Info) = {
                        local result = T;
                        if ((/^S0$/ in rec$conn_state) && (!Site::is_local_addr(rec$id$orig_h)))
                            result = F;
                        return result;
                        }
                        ]);
}