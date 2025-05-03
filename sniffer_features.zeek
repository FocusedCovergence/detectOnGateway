@load base/protocols/conn
@load protocols/conn/conn-size 

module ExtractFeatures;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;                    
        src_ip: addr &log;                 # IPV4_SRC_ADDR
        src_port: port &log;               # L4_SRC_PORT
        dst_ip: addr &log;                 # IPV4_DST_ADDR
        dst_port: port &log;               # L4_DST_PORT
        proto: string &log;                # PROTOCOL
        service: string &log;              # L7_PROTO
        in_bytes: count &log;              # IN_BYTES
        out_bytes: count &log;             # OUT_BYTES
        in_pkts: count &log;               # IN_PKTS
        out_pkts: count &log;              # OUT_PKTS
        tcp_flags: string &log;            # TCP_FLAGS
        duration_ms: double &log;          # FLOW_DURATION_MILLISECONDS
    };
}


event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info]);
    }


event connection_finished(c: connection)
    {
    if ( c?$id && c?$orig_h && c?$resp_h )
        {
        local src_ip = c$id$orig_h;
        local src_port = c$id$orig_p;
        local dst_ip = c$id$resp_h;
        local dst_port = c$id$resp_p;
        local proto = c$id$proto;
        local service = if (c?$service) c$service else "-";
        local in_bytes = if (c?$orig_bytes) c$orig_bytes else 0;
        local out_bytes = if (c?$resp_bytes) c$resp_bytes else 0;
        local in_pkts = if (c?$orig_pkts) c$orig_pkts else 0;
        local out_pkts = if (c?$resp_pkts) c$resp_pkts else 0;
        local tcp_flags = if (c?$history) c$history else "-";
        local duration_ms = if (c?$duration) c$duration * 1000.0 else 0.0;

        local info: Info = [$ts=network_time(),
                            $src_ip=src_ip,
                            $src_port=src_port,
                            $dst_ip=dst_ip,
                            $dst_port=dst_port,
                            $proto=proto,
                            $service=service,
                            $in_bytes=in_bytes,
                            $out_bytes=out_bytes,
                            $in_pkts=in_pkts,
                            $out_pkts=out_pkts,
                            $tcp_flags=tcp_flags,
                            $duration_ms=duration_ms];

        Log::write(LOG, info);
        }
    }