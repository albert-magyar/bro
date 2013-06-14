##! TCP Scan detection
##!
##! ..Authors: Sheharbano Khattak
##!            Seth Hall
##!            All the authors of the old scan.bro

@load base/frameworks/notice
@load base/frameworks/sumstats

@load base/utils/time

module Scan;

export {
	redef enum Notice::Type += {
		## Address scans detect that a host appears to be scanning some number
		## of destinations on a single port. This notice is generated when more
		## than :bro:id:`Scan::addr_scan_threshold` unique hosts are seen over
		## the previous :bro:id:`Scan::addr_scan_interval` time range.
		Address_Scan,

		## Port scans detect that an attacking host appears to be scanning a
		## single victim host on several ports.  This notice is generated when
		## an attacking host attempts to connect to
		## :bro:id:`Scan::port_scan_threshold`
		## unique ports on a single host over the previous
		## :bro:id:`Scan::port_scan_interval` time range.
		Port_Scan,
	};

	## Failed connection attempts are tracked over this time interval for the address
	## scan detection.  A higher interval will detect slower scanners, but may also
	## yield more false positives.
	const addr_scan_interval = 5min &redef;

	## Failed connection attempts are tracked over this time interval for the port scan
	## detection.  A higher interval will detect slower scanners, but may also yield
	## more false positives.
	const port_scan_interval = 5min &redef;

	## The threshold of a unique number of hosts a scanning host has to have failed
	## connections with on a single port.
	const addr_scan_threshold = 25 &redef;

	## The threshold of a number of unique ports a scanning host has to have failed
	## connections with on a single victim host.
	const port_scan_threshold = 15 &redef;

	## Custom thresholds based on service for address scan.  This is primarily
	## useful for setting reduced thresholds for specific ports.
	const addr_scan_custom_thresholds: table[port] of count &redef;

	global Scan::addr_scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);
	global Scan::port_scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);
}

event bro_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="scan.addr.fail", $apply=set(SumStats::UNIQUE)];
	SumStats::create([$epoch=addr_scan_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return double_to_count(result["scan.addr.fail"]$unique);
	                  	},
	                  #$threshold_func=check_addr_scan_threshold,
	                  $threshold=addr_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scan.addr.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local message=fmt("%s scanned at least %d unique hosts on port %s in %s", key$host, r$unique, key$str, dur);
	                  	NOTICE([$note=Address_Scan,
	                  	        $src=key$host,
	                  	        $p=to_port(key$str),
	                  	        $sub=side,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);

	# Note: port scans are tracked similar to: table[src_ip, dst_ip] of set(port);
	local r2: SumStats::Reducer = [$stream="scan.port.fail", $apply=set(SumStats::UNIQUE)];
	SumStats::create([$epoch=port_scan_interval,
	                  $reducers=set(r2),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return double_to_count(result["scan.port.fail"]$unique);
	                  	},
	                  $threshold=port_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scan.port.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local message = fmt("%s scanned at least %d unique ports of host %s in %s", key$host, r$unique, key$str, dur);
	                  	NOTICE([$note=Port_Scan,
	                  	        $src=key$host,
	                  	        $dst=to_addr(key$str),
	                  	        $sub=side,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

function add_sumstats(id: conn_id, reverse: bool)
	{
	local scanner      = id$orig_h;
	local victim       = id$resp_h;
	local scanned_port = id$resp_p;

	if ( reverse )
		{
		scanner      = id$resp_h;
		victim       = id$orig_h;
		scanned_port = id$orig_p;
		}

	if ( hook Scan::addr_scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.addr.fail", [$host=scanner, $str=cat(scanned_port)], [$str=cat(victim)]);

	if ( hook Scan::port_scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.port.fail", [$host=scanner, $str=cat(victim)], [$str=cat(scanned_port)]);
	}

function is_failed_conn(c: connection): bool
	{
	# Sr || ( (hR || ShR) && (data not sent in any direction) )
	if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
	     (((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
	       (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )
	      ) && /[Dd]/ !in c$history )
	   )
		return T;
	return F;
	}

function is_reverse_failed_conn(c: connection): bool
	{
	# reverse scan i.e. conn dest is the scanner
	# sR || ( (Hr || sHr) && (data not sent in any direction) )
	if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
	     (((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
	       (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history )
	      ) && /[Dd]/ !in c$history )
	   )
		return T;
	return F;
	}

## Generated for an unsuccessful connection attempt. This
## event is raised when an originator unsuccessfully attempted
## to establish a connection. “Unsuccessful” is defined as at least
## tcp_attempt_delay seconds having elapsed since the originator first sent a
## connection establishment packet to the destination without seeing a reply.
event connection_attempt(c: connection)
	{
	local is_reverse_scan = F;
	if ( "H" in c$history )
		is_reverse_scan = T;

	add_sumstats(c$id, is_reverse_scan);
	}

## Generated for a rejected TCP connection. This event is raised when an originator
## attempted to setup a TCP connection but the responder replied with a RST packet
## denying it.
event connection_rejected(c: connection)
	{
	local is_reverse_scan = F;
	if ( "s" in c$history )
		is_reverse_scan = T;

	add_sumstats(c$id, is_reverse_scan);
	}

## Generated when an endpoint aborted a TCP connection. The event is raised when
## one endpoint of an *established* TCP connection aborted by sending a RST packet.
event connection_reset(c: connection)
	{
	if ( is_failed_conn(c) )
		add_sumstats(c$id, F);
	else if ( is_reverse_failed_conn(c) )
		add_sumstats(c$id, T);
	}

## Generated for each still-open connection when Bro terminates.
event connection_pending(c: connection)
	{
	if ( is_failed_conn(c) )
		add_sumstats(c$id, F);
	else if ( is_reverse_failed_conn(c) )
		add_sumstats(c$id, T);
	}
