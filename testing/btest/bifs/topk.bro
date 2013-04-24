# @TEST-EXEC: bro -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

event bro_init() 
	{
	local k1 = topk_init(2);
	
	# first - peculiarity check...
	topk_add(k1, "a");
	topk_add(k1, "b");
	topk_add(k1, "b");
	topk_add(k1, "c");

	local s = topk_get_top(k1, 5);
	print s;
	print topk_count(k1, "a");
	print topk_epsilon(k1, "a");
	print topk_count(k1, "b");
	print topk_epsilon(k1, "b");
	print topk_count(k1, "c");
	print topk_epsilon(k1, "c");
 
	topk_add(k1, "d");
	s = topk_get_top(k1, 5);
	print s;
	print topk_count(k1, "b");
	print topk_epsilon(k1, "b");
	print topk_count(k1, "c");
	print topk_epsilon(k1, "c");
	print topk_count(k1, "d");
	print topk_epsilon(k1, "d");
	
	topk_add(k1, "e");
	s = topk_get_top(k1, 5);
	print s;
	print topk_count(k1, "d");
	print topk_epsilon(k1, "d");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");
	
	topk_add(k1, "f");
	s = topk_get_top(k1, 5);
	print s;
	print topk_count(k1, "f");
	print topk_epsilon(k1, "f");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");
	
	topk_add(k1, "e");
	s = topk_get_top(k1, 5);
	print s;
	print topk_count(k1, "f");
	print topk_epsilon(k1, "f");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");

	topk_add(k1, "g");
	s = topk_get_top(k1, 5);
	print s;
	print topk_count(k1, "f");
	print topk_epsilon(k1, "f");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "e");
	print topk_count(k1, "g");
	print topk_epsilon(k1, "g");

	k1 = topk_init(100);
	topk_add(k1, "a");
	topk_add(k1, "b");
	topk_add(k1, "b");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "c");
	topk_add(k1, "d");
	topk_add(k1, "d");
	topk_add(k1, "d");
	topk_add(k1, "d");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "e");
	topk_add(k1, "f");
	s = topk_get_top(k1, 3);
	print s;
	print topk_count(k1, "c");
	print topk_epsilon(k1, "c");
	print topk_count(k1, "e");
	print topk_epsilon(k1, "d");
	print topk_count(k1, "d");
	print topk_epsilon(k1, "d");
	
	local k3 = topk_init(2);
	topk_merge(k3, k1);

	s = topk_get_top(k3, 3);
	print s;
	print topk_count(k3, "c");
	print topk_epsilon(k3, "c");
	print topk_count(k3, "e");
	print topk_epsilon(k3, "e");
	print topk_count(k3, "d");
	print topk_epsilon(k3, "d");
	
	topk_merge(k3, k1);

	s = topk_get_top(k3, 3);
	print s;
	print topk_count(k3, "c");
	print topk_epsilon(k3, "c");
	print topk_count(k3, "e");
	print topk_epsilon(k3, "e");
	print topk_count(k3, "d");
	print topk_epsilon(k3, "d");

}
