-- SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

function decode(input)
	return {
		upatch = input.upatch,
		map = input.map,
		schema = 1,
		data = { records = {{ name = "first", count = 1 }} },
	}
end
