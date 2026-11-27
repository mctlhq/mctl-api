#!/usr/bin/env python3
"""TCP forwarder run in the sidecar container, which is the only container
attached to both the internal (no egress) network and the default bridge.
usage: fwd.py <listen_port>=<host>:<port> ..."""
import asyncio, sys
async def pipe(r, w):
    try:
        while (d := await r.read(65536)):
            w.write(d); await w.drain()
    except Exception: pass
    finally:
        try: w.close()
        except Exception: pass
def handler(host, port):
    async def h(cr, cw):
        try: ur, uw = await asyncio.open_connection(host, port)
        except Exception: cw.close(); return
        await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
    return h
async def main():
    for spec in sys.argv[1:]:
        lp, _, dest = spec.partition("="); host, _, port = dest.rpartition(":")
        await asyncio.start_server(handler(host, int(port)), "0.0.0.0", int(lp))
        print("fwd", lp, "->", dest, flush=True)
    await asyncio.Event().wait()
asyncio.run(main())
