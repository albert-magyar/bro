@load base/frameworks/notice
@load base/utils/addrs
@load base/utils/directions-and-hosts

module MIME;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Time when the message was first seen.
        ts:                time            &log;
        ## Unique ID for the connection.
        uid:               string          &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:                conn_id         &log;
        ## A count to represent the depth of this message transaction in a single 
        ## connection where multiple messages were transferred.
        trans_depth:       count           &log &default=1;
        ## Contents of the Helo header.
        helo:              string          &log &optional;
        ## Contents of the From header.
        mailfrom:          string          &log &optional;
        ## Contents of the Rcpt header.
        rcptto:            set[string]     &log &optional;
        ## Contents of the Date header.
        date:              string          &log &optional;
        ## Contents of the From header.
        from:              string          &log &optional;
        ## Contents of the To header.
        to:                set[string]     &log &optional;
        ## Contents of the ReplyTo header.
        reply_to:          string          &log &optional;
        ## Contents of the MsgID header.
        msg_id:            string          &log &optional;
        ## Contents of the In-Reply-To header.
        in_reply_to:       string          &log &optional;
        ## Contents of the Subject header.
        subject:           string          &log &optional;
        ## Contents of the X-Origininating-IP header.
        x_originating_ip:  addr            &log &optional;
        ## Contents of the first Received header.
        first_received:    string          &log &optional;
        ## Contents of the second Received header.
        second_received:   string          &log &optional;
        ## The message transmission path, as extracted from the headers.
        path:              vector of addr  &log &optional;
        ## Value of the User-Agent header from the client.
        user_agent:        string          &log &optional;
        ## Indicates if the "Received: from" headers should still be processed.
        process_received_from: bool        &default=T;
    };
	
    ## Direction to capture the full "Received from" path.
    ##    REMOTE_HOSTS - only capture the path until an internal host is found.
    ##    LOCAL_HOSTS - only capture the path until the external host is discovered.
    ##    ALL_HOSTS - always capture the entire path.
    ##    NO_HOSTS - never capture the path.
    const mail_path_capture = ALL_HOSTS &redef;
	
    ## Create an extremely shortened representation of a log line.
    global describe: function(rec: Info): string;

    global log_mime: event(rec: Info);
}

redef record connection += { 
    mime:       Info  &optional;
};

event bro_init() &priority=5 {
    Log::create_stream(MIME::LOG, [$columns=MIME::Info, $ev=log_mime]);
}
	
function find_address_in_mime_header(header: string): string {
    local ips = find_ip_addresses(header);
    if (|ips| > 1) {
        return ips[1];
    } else if (|ips| > 0) {
        return ips[0];
    } else {
        return "";
    }
}

event mime_begin_entity(c: connection) &priority=5 {
    local i: Info;
    i$ts=network_time();
    i$uid=c$uid;
    i$id=c$id;
    if (c?$mime) {
        i$trans_depth = c$mime$trans_depth + 1;
    }
    i$path = vector(c$id$resp_h, c$id$orig_h);
    c$mime = i;
}

event mime_one_header(c: connection, h: mime_header_rec) &priority=5 {
    if (!c?$mime) return;
    switch (h$name) {
        case "MESSAGE-ID":
            c$mime$msg_id = h$value;
            break;
        case "RECEIVED":
            if (c$mime?$first_received) {
                c$mime$second_received = c$mime$first_received;
            }
            c$mime$first_received = h$value;
            break;
        case "IN-REPLY-TO":
            c$mime$in_reply_to = h$value;
            break;
        case "SUBJECT":
            c$mime$subject = h$value;
            break;
        case "FROM":
            c$mime$from = h$value;
            break;
        case "REPLY-TO":
            c$mime$reply_to = h$value;
            break;
        case "DATE":
            c$mime$date = h$value;
            break;
        case "TO":
            if (!c$mime?$to) {
                c$mime$to = set();
            }
            local to_parts = split(h$value, /[[:blank:]]*,[[:blank:]]*/);
            for (i in to_parts) {
                add c$mime$to[to_parts[i]];
            }
            break;
        case "X-ORIGINATING-IP":
            local addresses = find_ip_addresses(h$value);
            if (1 in addresses) {
                c$mime$x_originating_ip = to_addr(addresses[1]);
	    }
            break;
	case "X-MAILER", "USER-AGENT", "X-USER-AGENT":
            c$mime$user_agent = h$value;
            break;
    }
}
	
# This event handler builds the "Received From" path by reading the 
# headers in the mail
event mime_one_header(c: connection, h: mime_header_rec) &priority=3 {
    if (h$name == "RECEIVED" && c$mime$process_received_from) {
        local text_ip = find_address_in_mime_header(h$value);
        if (text_ip == "") return;
        local ip = to_addr(text_ip);
        if (!addr_matches_host(ip, mail_path_capture) && !Site::is_private_addr(ip)) {
            c$mime$process_received_from = F;
        }
        if (c$mime$path[|c$mime$path|-1] != ip) {
            c$mime$path[|c$mime$path|] = ip;
        }
    }
}

event mime_end_entity(c: connection) &priority=-5 {
    if (c?$mime) {
        Log::write(MIME::LOG, c$mime);
    }
}

event connection_state_remove(c: connection) &priority=-5 {

}

function describe(rec: Info): string {
    if (rec?$mailfrom && rec?$rcptto) {
        local one_to = "";
        for (to in rec$rcptto) {
            one_to = to;
            break;
        }
        local abbrev_subject = "";
        if (rec?$subject) {
            if (|rec$subject| > 20) {
                abbrev_subject = rec$subject[0:20] + "...";
            }
        }

        return fmt("%s -> %s%s%s", rec$mailfrom, one_to,
            (|rec$rcptto|>1 ? fmt(" (plus %d others)", |rec$rcptto|-1) : ""),
            (abbrev_subject != "" ? fmt(": %s", abbrev_subject) : ""));
    } else {
        return "";
    }
}
