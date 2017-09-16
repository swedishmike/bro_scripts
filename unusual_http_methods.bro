@load base/frameworks/notice
@load base/protocols/http

module UnusualHTTP;

export {
    redef enum Notice::Type += {
        Interesting_HTTP_Method_Success,
        Interesting_HTTP_Method_Fail,
    };

    redef enum HTTP::Tags += {
        HTTP_BAD_METHOD_OK,
        HTTP_BAD_METHOD_FAIL,
    };


    const suspicious_http_methods: set[string] = {
        "DELETE", "TRACE", "CONNECT",
        "PROPPATCH", "MKCOL", "SEARCH",
        "COPY", "MOVE", "LOCK", "UNLOCK",
        "POLL", "REPORT", "SUBSCRIBE", "BMOVE"
    } &redef;

    const monitor_ip_spaces: set[subnet] &redef;
    const monitor_ports: set[port] &redef;
    const ignore_hosts_orig: set[subnet] &redef;
    const ignore_hosts_resp: set[subnet] &redef;
}


event http_reply(c: connection, version: string, code: count, reason: string)
{
  local cluster_client_ip: addr;

  if ( ! c?$http )
    return;
  if ( ! c$http?$method )
    return;
  if ( c$http$method ! in suspicious_http_methods )
    return;
  else {
            if ( c$http$status_code < 300 ) {
                add c$http$tags[HTTP_BAD_METHOD_OK];
                NOTICE([$note=Interesting_HTTP_Method_Success,
                    $msg=fmt("%s successfully used method %s on %s host %s", c$id$orig_h, c$http$method, c$id$resp_h, c$http$host),
                    $uid=c$uid,
                    $id=c$id,
                    $identifier=cat(c$http$host,c$http$method,c$id$orig_h)]);
            } else {
                add c$http$tags[HTTP_BAD_METHOD_FAIL];
                NOTICE([$note=Interesting_HTTP_Method_Fail,
                    $msg=fmt("%s failed to use method %s on %s host %s", c$id$orig_h, c$http$method, c$id$resp_h, c$http$host),
                    $uid=c$uid,
                    $id=c$id,
                    $identifier=cat(c$http$host,c$http$method,c$id$orig_h)]);
            }
        }

}