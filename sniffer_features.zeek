@load base/protocols/conn

module NetflowExtract;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:              time;
        uid:             string;
        src_ip:          addr;
        src_port:        port;
        dst_ip:          addr;
        dst_port:        port;
        proto:           count;
        in_bytes:        count;
        out_bytes:       count;
        in_pkts:         count;
        out_pkts:        count;
        tcp_flags:       string;
        duration_ms:     double;
    };
}

global log_netflow: log_id = Log::create_stream(NetflowExtract::LOG, [$columns=NetflowExtract::Info]);

event zeek_init() {
    Log::write_header(log_netflow, "NetFlow-like Features");
}

event connection_state_remove(c: connection) {
    local proto = c$id$resp_p == 0 ? 0 : c$id$proto;  # fallback if port unknown

    local in_bytes = c$orig$size;
    local out_bytes = c$resp$size;
    local in_pkts = c$orig$num_pkts;
    local out_pkts = c$resp$num_pkts;

    local flags = "";
    if (c$history != null) {
        flags = c$history;
    }

    local dur = 0.0;
    if (c$duration != null) {
        dur = c$duration * 1000.0;  # seconds to ms
    }

    local r: Info = [$ts=c$start_time,
                     $uid=c$uid,
                     $src_ip=c$id$orig_h,
                     $src_port=c$id$orig_p,
                     $dst_ip=c$id$resp_h,
                     $dst_port=c$id$resp_p,
                     $proto=proto,
                     $in_bytes=in_bytes,
                     $out_bytes=out_bytes,
                     $in_pkts=in_pkts,
                     $out_pkts=out_pkts,
                     $tcp_flags=flags,
                     $duration_ms=dur];

    Log::write(log_netflow, r);
}