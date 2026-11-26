-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

local RECORD = 120
local ROLES = { [1] = "initiator", [2] = "acceptor", [3] = "listener" }
local PROTOS = { [1] = "icmp", [6] = "tcp", [17] = "udp", [58] = "icmpv6",
	[132] = "sctp", [136] = "udplite" }

local function ipv4(value)
	local n = tonumber(value) or 0
	return string.format("%d.%d.%d.%d", n % 256,
		math.floor(n / 256) % 256, math.floor(n / 65536) % 256,
		math.floor(n / 16777216) % 256)
end

local function ipv6(a, b, c, d)
	local words = {}
	for _, value in ipairs({a, b, c, d}) do
		local n = tonumber(value) or 0
		words[#words + 1] = string.format("%02x%02x", n % 256,
			math.floor(n / 256) % 256)
		words[#words + 1] = string.format("%02x%02x",
			math.floor(n / 65536) % 256,
			math.floor(n / 16777216) % 256)
	end
	return table.concat(words, ":")
end

local function address(slot, family)
	if family == 2 then
		return ipv4(slot:u32(40))
	elseif family == 10 then
		return ipv6(slot:u32(40), slot:u32(44), slot:u32(48), slot:u32(52))
	end
	return nil
end

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
	local family, proto = slot:u8(32), slot:u8(33)
	return {
		entry_index = slot:u32(0),
		executable = { dev = slot:u32(8), ino = slot:u64(16) },
		cgroup_id = slot:u64(24),
		family = family,
		proto = PROTOS[proto] or proto,
		role = ROLES[slot:u8(34)],
		address = address(slot, family),
		port = slot:u16(36),
		count = slot:u64(56),
		first_seen_unix_nano = unix_nano(input, hdr, slot:u64(64)),
		last_seen_unix_nano = unix_nano(input, hdr, slot:u64(72)),
		tx_packets = slot:u64(80),
		tx_bytes = slot:u64(88),
		rx_packets = slot:u64(96),
		rx_bytes = slot:u64(104),
		pid = slot:u32(112),
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
