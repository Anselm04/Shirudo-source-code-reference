-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause

local function command(hex)
	local name = {}

	for i = 1, #hex - 1, 2 do
		local byte = tonumber(hex:sub(i, i + 1), 16)

		if byte == 0 then
			break
		end
		name[#name + 1] = string.char(byte)
	end
	return table.concat(name)
end

function decode(input)
	local execs = {}

	for _, entry in ipairs(input.data.entries) do
		execs[#execs + 1] = {
			command = command(entry.key_hex),
			count = tonumber(shirudo.hex_u64(entry.value_hex, 0)),
		}
	end
	table.sort(execs, function(a, b) return a.count > b.count end)
	return { execs = execs }
end
