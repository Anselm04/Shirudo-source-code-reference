-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

local RECORD = 224
local KINDS = {
	[1] = "setuid_root",
	[2] = "cred_anomaly",
	[3] = "ptrace_attach",
	[4] = "mount",
	[5] = "kernel_read_file",
	[6] = "kernel_load_data",
	[7] = "module_request",
	[8] = "userns_create",
	[9] = "bpf",
	[10] = "mmap_exec",
	[11] = "mprotect_exec",
}

local function header(slot)
	return {
		boot_now_ns = slot:u64(32),
		since_ns = slot:u64(40),
		used = slot:u32(48),
		overflow = slot:u32(52),
		lost = slot:u32(56),
		peek = slot:u32(28) % 2 == 1,
	}
end

local function unix_nano(input, hdr, ts)
	if ts == "0" then
		return nil
	end
	return shirudo.u64_sub(input.timeUnixNano,
		shirudo.u64_sub(hdr.boot_now_ns, ts))
end

local function interval(input, hdr)
	return {
		since_unix_nano = unix_nano(input, hdr, hdr.since_ns),
		used = hdr.used,
		overflow = hdr.overflow,
		lost = hdr.lost,
		peek = hdr.peek,
	}
end

local function record(input, hdr, slot)
	local kind = slot:u32(32)
	return {
		entry_index = slot:u32(0),
		executable = { dev = slot:u32(8), ino = slot:u64(16) },
		cgroup_id = slot:u64(24),
		kind = KINDS[kind] or kind,
		subtype = slot:u32(36),
		euid = slot:u32(40),
		uid = slot:u32(44),
		count = slot:u64(48),
		first_seen_unix_nano = unix_nano(input, hdr, slot:u64(56)),
		last_seen_unix_nano = unix_nano(input, hdr, slot:u64(64)),
		pid = slot:u32(72),
		aux = slot:u64(80),
		name = slot:cstring(88, 32),
		detail = slot:cstring(120, 96),
	}
end

function decode(input)
	local records, summary = {}, nil
	for _, page in ipairs(input.data.pages) do
		local slots = shirudo.page_slots(page, RECORD)
		local hdr = slots[1] and header(slots[1])
		if hdr then
			summary = summary or interval(input, hdr)
			for i = 2, #slots do
				if slots[i]:u32(4) % 2 == 1 then
					records[#records + 1] = record(input, hdr, slots[i])
				end
			end
		end
	end
	return {
		schema = 1,
		upatch = input.upatch,
		map = input.map,
		interval = summary,
		records = records,
	}
end
