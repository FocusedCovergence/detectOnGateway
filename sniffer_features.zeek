@load base/protocols/conn

module ExtractFeatures;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        proto: string &log;
        service: string &log;
        in_bytes: count &log;
        out_bytes: count &log;
        tcp_flags: string &log;
        duration_ms: double &log;
    };
}

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="extract_features"]);
}

event connection_finished(c: connection) {
    local service = "-";
    if ( c?$service ) {
        service = fmt("%s", c$service);
    }

    local in_bytes = 0;
    if ( c?$orig && c$orig?$size ) {
        in_bytes = c$orig$size;
    }

    local out_bytes = 0;
    if ( c?$resp && c$resp?$size ) {
        out_bytes = c$resp$size;
    }

    local tcp_flags = "-";
    if ( c?$history ) {
        tcp_flags = c$history;
    }

    local duration_ms = 0.0;
    if ( c?$duration ) {
        duration_ms = |c$duration| * 1000.0;
    }

    local info: Info = [$ts=network_time(),
                        $src_ip=c$id$orig_h,
                        $src_port=c$id$orig_p,
                        $dst_ip=c$id$resp_h,
                        $dst_port=c$id$resp_p,
                        $proto=fmt("%s", c$id$proto),
                        $service=service,
                        $in_bytes=in_bytes,
                        $out_bytes=out_bytes,
                        $tcp_flags=tcp_flags,
                        $duration_ms=duration_ms];

    Log::write(LOG, info);
}


