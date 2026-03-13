import asyncio

from mail_sovereignty.smtp import fetch_smtp_banner


class TestFetchSmtpBanner:
    async def test_microsoft_banner(self):
        async def handler(reader, writer):
            writer.write(
                b"220 BL02EPF0001CA17.mail.protection.outlook.com Microsoft ESMTP MAIL Service ready\r\n"
            )
            await writer.drain()
            await reader.readline()  # EHLO
            writer.write(b"250 BL02EPF0001CA17.mail.protection.outlook.com Hello\r\n")
            await writer.drain()
            await reader.readline()  # QUIT
            writer.write(b"221 Bye\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            # Monkey-patch to use our port
            result = await _fetch_with_port("127.0.0.1", port)
        assert "Microsoft ESMTP MAIL Service" in result["banner"]
        assert "250" in result["ehlo"]

    async def test_google_banner(self):
        async def handler(reader, writer):
            writer.write(b"220 mx.google.com ESMTP ready\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"250-mx.google.com at your service\r\n")
            writer.write(b"250 SIZE 157286400\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"221 Bye\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            result = await _fetch_with_port("127.0.0.1", port)
        assert "mx.google.com" in result["banner"]

    async def test_postfix_banner(self):
        async def handler(reader, writer):
            writer.write(b"220 mail.example.ch ESMTP Postfix\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"250 mail.example.ch\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"221 Bye\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            result = await _fetch_with_port("127.0.0.1", port)
        assert "Postfix" in result["banner"]

    async def test_connection_refused(self):
        # Use a hostname that will fail DNS resolution
        result = await fetch_smtp_banner("host.invalid", timeout=1.0)
        assert result["banner"] == ""
        assert result["ehlo"] == ""

    async def test_timeout(self):
        async def handler(reader, writer):
            # Never respond
            await asyncio.sleep(30)

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            result = await _fetch_with_port("127.0.0.1", port, timeout=0.5)
        assert result["banner"] == ""

    async def test_quit_always_sent(self):
        quit_received = []

        async def handler(reader, writer):
            writer.write(b"220 test.example.ch ESMTP\r\n")
            await writer.drain()
            data = await reader.readline()  # EHLO
            writer.write(b"250 test.example.ch\r\n")
            await writer.drain()
            data = await reader.readline()  # QUIT
            if data.strip().upper() == b"QUIT":
                quit_received.append(True)
            writer.write(b"221 Bye\r\n")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            await _fetch_with_port("127.0.0.1", port)
        assert quit_received


async def _fetch_with_port(
    host: str, port: int, timeout: float = 5.0
) -> dict[str, str]:
    """Helper: call fetch_smtp_banner with monkey-patched connection."""
    from unittest.mock import patch

    original_open = asyncio.open_connection

    async def patched_open(h, p, **kwargs):
        return await original_open(host, port, **kwargs)

    with patch("asyncio.open_connection", side_effect=patched_open):
        return await fetch_smtp_banner(h if (h := host) else host, timeout=timeout)
