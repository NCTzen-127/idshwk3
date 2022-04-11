global agentOfAddr :table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string) {
	local orig_addr: addr = c$id$orig_h;
	if (c$http?$user_agent){
		local agent: string = to_lower(c$http$user_agent);
		if (orig_addr in agentOfAddr) {
			add agentOfAddr[orig_addr][agent];
		} else {
			agentOfAddr[orig_addr] = set(agent);
		}
	}
}

event zeek_done() {
	for (orig_addr in agentOfAddr) {
		if (|agentOfAddr[orig_addr]| >= 3) {
			print(addr_to_uri(orig_addr) + " is a proxy");
		}
	}
}
