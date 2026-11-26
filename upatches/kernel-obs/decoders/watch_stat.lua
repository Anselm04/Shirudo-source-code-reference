-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

local function metric_point(input, value, outcome)
	return {
		startTimeUnixNano = input.startTimeUnixNano,
		timeUnixNano = input.timeUnixNano,
		asInt = value,
		attributes = {
			{key = "outcome", value = {stringValue = outcome}},
		},
	}
end

function decode(input)
	local data = input.data
	local entry = data.entries and data.entries[1]
	if not entry then
		error("missing watch counter entry")
	end
	local stride = math.ceil((data.value_size or 16) / 8) * 8
	local cpus = data.n_cpus or 1
	local checked, matched = "0", "0"
	for cpu = 0, cpus - 1 do
		local base = cpu * stride
		checked = shirudo.u64_add(checked,
			shirudo.hex_u64(entry.value_hex, base))
		matched = shirudo.u64_add(matched,
			shirudo.hex_u64(entry.value_hex, base + 8))
	end
	return {
		{name = "kernel_obs.watch_attempts", unit = "1",
			description = "socket-level destination checks against the watch list",
			sum = {
				aggregationTemporality = 2,
				isMonotonic = true,
				dataPoints = {
					metric_point(input, checked, "checked"),
					metric_point(input, matched, "matched"),
				},
			}},
	}
end
