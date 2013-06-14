@load base/frameworks/intel
@load base/protocols/smtp/file-analysis
@load base/utils/urls
@load ./where-locations

event intel_mime_data(f: fa_file, data: string)
	{
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		local urls = find_all_urls_without_scheme(data);
		for ( url in urls )
			{
			Intel::seen([$str=url,
			             $str_type=Intel::URL,
			             $conn=c,
			             $where=SMTP::IN_MESSAGE]);
			}
		}
	}

event file_new(f: fa_file) &priority=5
	{
	if ( ! f?$source ) return;
	if ( f$source != "SMTP" ) return;

	FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_DATA_EVENT,
	                               $stream_event=intel_mime_data]);
	}
