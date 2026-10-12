import asyncio
import os
import pytest
from network.testbed.socket_traffic import UDPResponder, exchange, tcp_server


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


@pytest.mark.skipif(os.name != 'posix',reason='Linux lab transport')
def test_persistent_tcp_two_exchanges_share_one_connection(monkeypatch):
    async def check():
        count=[]
        async def server(reader,writer):
            count.append(writer.get_extra_info('peername'))
            await tcp_server(reader,writer)
        listener=await asyncio.start_server(server,'127.0.0.1',0)
        original=asyncio.open_connection
        async def redirect(host,port,**kw):return await original('127.0.0.1',listener.sockets[0].getsockname()[1])
        monkeypatch.setattr(asyncio,'open_connection',redirect)
        try:
            segments=[dict(offset=t,request_bytes=100,response_bytes=200,duration=.01) for t in (0,.05)]
            await asyncio.wait_for(exchange(dict(destination='10.0.0.100',proto='tcp',port=443,request_bytes=100,response_bytes=200,duration=.06,segments=segments)),1)
            assert len(count)==1
        finally:listener.close();await listener.wait_closed()
    asyncio.run(check())


@pytest.mark.skipif(os.name != 'posix',reason='Linux lab transport')
def test_persistent_udp_keeps_source_port(monkeypatch):
    async def check():
        loop=asyncio.get_running_loop();seen=[]
        transport,_=await loop.create_datagram_endpoint(UDPResponder,local_addr=('127.0.0.1',0))
        original=loop.sock_sendto
        async def redirect(sock,data,address):
            result=await original(sock,data,transport.get_extra_info('sockname'));seen.append(sock.getsockname()[1]);return result
        monkeypatch.setattr(loop,'sock_sendto',redirect)
        try:
            segments=[dict(offset=t,request_bytes=48,response_bytes=48,duration=.01) for t in (0,.05)]
            await asyncio.wait_for(exchange(dict(destination='10.0.0.100',proto='udp',port=53,request_bytes=48,response_bytes=48,duration=.06,segments=segments)),1)
            assert len(seen)==2 and seen[0]==seen[1]
        finally:transport.close()
    asyncio.run(check())
