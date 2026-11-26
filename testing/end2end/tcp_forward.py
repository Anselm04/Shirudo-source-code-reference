#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Forward a TCP port to another address, so the guest reaches the host's
registry under the address the operator published the tree with."""

import asyncio
import sys


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def main(listen, target, ready):
    lhost, lport = listen.rsplit(":", 1)
    thost, tport = target.rsplit(":", 1)

    async def handle(reader, writer):
        try:
            treader, twriter = await asyncio.open_connection(thost, int(tport))
        except OSError:
            writer.close()
            return
        await asyncio.gather(pipe(reader, twriter), pipe(treader, writer),
                             return_exceptions=True)

    server = await asyncio.start_server(handle, lhost, int(lport))
    with open(ready, "w") as f:
        f.write("ready\n")
    async with server:
        await server.serve_forever()


asyncio.run(main(*sys.argv[1:4]))
