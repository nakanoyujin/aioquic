#connectメソッドで呼び出される
import asyncio
import ipaddress
import socket
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Callable, Optional, cast

from ..quic.configuration import QuicConfiguration
from ..quic.connection import QuicConnection
from ..tls import SessionTicketHandler
from .protocol import QuicConnectionProtocol, QuicStreamHandler

__all__ = ["connect"]

# keep compatibility for Python 3.7 on Windows
if not hasattr(socket, "IPPROTO_IPV6"):
    socket.IPPROTO_IPV6 = 41


@asynccontextmanager
async def connect(
    host: str,
    port: int,
    *,
    configuration: Optional[QuicConfiguration] = None,
    create_protocol: Optional[Callable] = QuicConnectionProtocol,
    session_ticket_handler: Optional[SessionTicketHandler] = None,
    stream_handler: Optional[QuicStreamHandler] = None,
    wait_connected: bool = True,
    local_port: int = 0,
) -> AsyncGenerator[QuicConnectionProtocol, None]:
    """
与えられた `host` と `port` にある QUIC サーバーに接続します。

    :meth:`connect()` は待ち受けを返します。待ち受けにすると
    class:`~aioquic.asyncio.QuicConnectionProtocol` を生成し、ストリームを作成するために使用することができます。
    ストリームを作成するために使用できます。

    func:`connect` は、以下のオプションの引数も受け付けます：

    * ``configuration`` は :class:`~aioquic.quic.configuration.QuicConfiguration` です。
      設定オブジェクトです。
    * ``create_protocol`` は接続を管理する :class:`~asyncio.Protocol` をカスタマイズすることができます。
      接続を管理する :class:`~asyncio.Protocol` をカスタマイズすることができます。これは :class:`~asyncio.Protocol` と同じ引数を受け取る callable または class である必要があります。
      クラス:`~asyncio.QuicConnectionProtocol`と同じ引数を受け取り、 :クラス:`~asyncio.Protocol`のインスタンスを返します。
      クラス:`~aioquic.asyncio.QuicConnectionProtocol` またはそのサブクラスのインスタンスを返します。
    * セッションチケットの受信時にTLSエンジンによって呼び出されるコールバックです。
      エンジンによって呼び出されるコールバックです。
    * ストリームが作成されるたびに呼び出されるコールバックです。
      ストリームが作成されるたびに呼び出されるコールバックです。このコールバックは2つの引数を受け取る必要があります。
      と :class:`asyncio.StreamWriter` の 2 つの引数を受け取る必要があります。
    * ``local_port`` は、このクライアントがバインドしたい UDP ポート番号です。
    """
    loop = asyncio.get_event_loop()
    local_host = "::"

    # if host is not an IP address, pass it to enable SNI
    try:
        ipaddress.ip_address(host)
        server_name = None
    except ValueError:
        server_name = host

    # lookup remote address
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:
        addr = ("::ffff:" + addr[0], addr[1], 0, 0)

    # prepare QUIC connection
    if configuration is None:
        configuration = QuicConfiguration(is_client=True)
    if configuration.server_name is None:
        configuration.server_name = server_name
    connection = QuicConnection(
        configuration=configuration, session_ticket_handler=session_ticket_handler
    )

    # explicitly enable IPv4/IPv6 dual stack
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    completed = False
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind((local_host, local_port, 0, 0))
        completed = True
    finally:
        if not completed:
            sock.close()
    # connect
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: create_protocol(connection, stream_handler=stream_handler),
        sock=sock,
    )
    protocol = cast(QuicConnectionProtocol, protocol)
    try:
        protocol.connect(addr)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()
