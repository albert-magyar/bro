# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff .stdout

event bro_init() &priority=5
	{
	local r1: SumStats::Reducer = [$stream="test.metric", 
	                               $apply=set(SumStats::SUM, 
	                                          SumStats::VARIANCE, 
	                                          SumStats::AVERAGE, 
	                                          SumStats::MAX, 
	                                          SumStats::MIN, 
	                                          SumStats::STD_DEV,
	                                          SumStats::UNIQUE,
						  SumStats::HLLUNIQUE)];
	SumStats::create([$epoch=3secs,
	                     $reducers=set(r1),
	                     $epoch_finished(data: SumStats::ResultTable) = 
	                     	{
	                     	for ( key in data )
	                     		{
	                     		local r = data[key]["test.metric"];
	                     		print fmt("Host: %s - num:%d - sum:%.1f - var:%.1f - avg:%.1f - max:%.1f - min:%.1f - std_dev:%.1f - unique:%d - hllunique:%d", key$host, r$num, r$sum, r$variance, r$average, r$max, r$min, r$std_dev, r$unique, r$hllunique);
	                     		}
	                     	}
		 ]);

	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=5]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=22]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=94]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=50]);
	SumStats::observe("test.metric", [$host=1.2.3.4], [$num=50]);

	SumStats::observe("test.metric", [$host=6.5.4.3], [$num=2]);
	SumStats::observe("test.metric", [$host=7.2.1.5], [$num=1]);
	}
