import asyncio
import os
import pytest
from network.testbed.socket_traffic import UDPResponder, exchange


@pytest.mark.skipif(os.name != 'posix', reason='The Mininet transport runs on Linux')
def test_udp_zero_response_is_one_way_and_tail_chunk_does_not_wait(monkeypatch):
    async def check():
        loop=asyncio.get_running_loop()
        transport,_=await loop.create_datagram_endpoint(UDPResponder,local_addr=('127.0.0.1',0))
        # Keep the production subnet restriction; only redirect the test's actual send.
        original=loop.sock_sendto
        async def redirect(sock,data,address):
            return await original(sock,data,('127.0.0.1',transport.get_extra_info('sockname')[1]))
        monkeypatch.setattr(loop,'sock_sendto',redirect)
        try:
            base={'destination':'10.0.0.100','proto':'udp','port':1900,'duration':.01}
            await asyncio.wait_for(exchange({**base,'request_bytes':48,'response_bytes':0}),.5)
            await asyncio.wait_for(exchange({**base,'request_bytes':1540,'response_bytes':92}),.5)
        finally: transport.close()
    asyncio.run(check())
