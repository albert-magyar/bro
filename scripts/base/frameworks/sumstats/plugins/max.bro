@load base/frameworks/sumstats

module SumStats;

export {
	redef enum Calculation += {
		## Find the maximum value.
		MAX
	};

	redef record ResultVal += {
		## For numeric data, this tracks the maximum value given.
		max: double &optional;
	};
}

hook observe_hook(r: Reducer, val: double, obs: Observation, rv: ResultVal)
	{
	if ( MAX in r$apply )
		{
		if ( ! rv?$max )
			rv$max = val;
		else if ( val > rv$max )
			rv$max = val;
		}
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( rv1?$max && rv2?$max )
		result$max = (rv1$max > rv2$max) ? rv1$max : rv2$max;
	else if ( rv1?$max )
		result$max = rv1$max;
	else if ( rv2?$max )
		result$max = rv2$max;
	}


