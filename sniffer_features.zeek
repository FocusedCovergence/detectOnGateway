@load base/protocols/conn

module ExtractFeatures;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        proto: string &log;
        service: string &log;
        in_bytes: count &log;
        out_bytes: count &log;
        in_pkts: count &log;
        out_pkts: count &log;
        tcp_flags: count &log;
        duration_ms: double &log;
    };
}

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info, $path="extract_features"]);
}

event connection_finished(c: connection) {

    local flag_map = {
        ["F"] = 1,
        ["S"] = 2,
        ["R"] = 4,
        ["P"] = 8,
        ["A"] = 16,
        ["U"] = 32,
        ["E"] = 64,
        ["C"] = 128
    };

    local tcpHis = "-";
    if (c?$history) {
        tcpHis = c$history;
    }

    local tcp_flag_val: count = 0;
    for ( ch in tcpHis ) {
        if ( ch in flag_map )
            tcp_flag_val += flag_map[ch];
    }


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

    local duration_ms = 0.0;
    if ( c?$duration ) {
        duration_ms = |c$duration| * 1000.0;
    }

    local in_pkts = 0;
    if ( c?$orig && c$orig?$num_pkts ) {
        in_pkts = c$orig$num_pkts;
    }

    local out_pkts = 0;
    if ( c?$resp && c$resp?$num_pkts ) {
        out_pkts = c$resp$num_pkts;
    }


    local info: Info = [$src_ip=c$id$orig_h,
                        $src_port=c$id$orig_p,
                        $dst_ip=c$id$resp_h,
                        $dst_port=c$id$resp_p,
                        $proto=fmt("%s", c$id$proto),
                        $service=service,
                        $in_bytes=in_bytes,
                        $out_bytes=out_bytes,
                        $in_pkts=in_pkts,
                        $out_pkts=out_pkts,
                        $tcp_flags=tcp_flag_val,
                        $duration_ms=duration_ms];

    Log::write(LOG, info);
}


