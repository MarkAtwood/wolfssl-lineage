// socketft.cpp - written and placed in the public domain by Wei Dai

#ifdef _MSC_VER

#include "pch.h"
#include "socketft.h"
#include <sstream>

NAMESPACE_BEGIN(CryptoPP)

static std::string IntToString(int i)
{
	std::ostringstream result;
	result << i;
	return result.str();
}

Socket::Err::Err(SOCKET s, const std::string& operation, int error)
	: Exception("SocketSink: error " + IntToString(error) + " during operation " + operation)
	, m_s(s), m_operation(operation), m_error(error)
{
}

Socket::~Socket()
{
	if (m_own && m_s != INVALID_SOCKET)
	{
		try
		{
			Close();
		}
		catch (...)
		{
		}
	}
}

void Socket::AttachSocket(SOCKET s, bool own)
{
	if (m_own && m_s != INVALID_SOCKET)
		Close();

	m_s = s;
	m_own = own;
	SocketChanged();
}

SOCKET Socket::DetachSocket()
{
	SOCKET s = m_s;
	m_s = INVALID_SOCKET;
	SocketChanged();
	return s;
}

void Socket::Create(int nType)
{
	assert(m_s == INVALID_SOCKET);
	m_s = socket(AF_INET, nType, 0);
	CheckAndHandleError("socket", m_s);
	m_own = true;
	SocketChanged();
}

void Socket::Close()
{
	assert(m_s != INVALID_SOCKET);
	CheckAndHandleError("closesocket", closesocket(m_s));
	m_s = INVALID_SOCKET;
	SocketChanged();
}

void Socket::Bind(unsigned int port, const char *addr)
{
	SOCKADDR_IN sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;

	if (addr == NULL)
		sa.sin_addr.s_addr = htonl(INADDR_ANY);
	else
	{
		unsigned long result = inet_addr(addr);
		if (result == INADDR_NONE)
			throw Err(m_s, "inet_addr", WSAEINVAL);
		sa.sin_addr.s_addr = result;
	}

	sa.sin_port = htons((u_short)port);

	Bind((sockaddr *)&sa, sizeof(sa));
}

void Socket::Bind(const sockaddr *psa, unsigned int saLen)
{
	assert(m_s != INVALID_SOCKET);
	CheckAndHandleError("bind", bind(m_s, psa, saLen));
}

void Socket::Listen(int backlog)
{
	assert(m_s != INVALID_SOCKET);
	CheckAndHandleError("listen", listen(m_s, backlog));
}

void Socket::Connect(const char *addr, unsigned int port)
{
	assert(addr != NULL);

	SOCKADDR_IN sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(addr);

	if (sa.sin_addr.s_addr == INADDR_NONE)
	{
		hostent *lphost = gethostbyname(addr);
		if (lphost == NULL)
			throw Err(m_s, "gethostbyname", WSAEINVAL);

		sa.sin_addr.s_addr = ((in_addr *)lphost->h_addr)->s_addr;
	}

	sa.sin_port = htons((u_short)port);

	Connect((sockaddr *)&sa, sizeof(sa));
}

void Socket::Connect(const sockaddr* psa, int saLen)
{
	assert(m_s != INVALID_SOCKET);
	int result = connect(m_s, psa, saLen);
	if (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
		return;
	CheckAndHandleError("connect", result);
}

bool Socket::Accept(Socket& target, sockaddr *psa, int *psaLen)
{
	assert(m_s != INVALID_SOCKET);
	SOCKET s = accept(m_s, psa, psaLen);
	if (s == INVALID_SOCKET && WSAGetLastError() == WSAEWOULDBLOCK)
		return false;
	CheckAndHandleError("accept", s);
	target.AttachSocket(s, true);
	return true;
}

unsigned int Socket::Send(const byte* buf, unsigned int bufLen, int flags)
{
	assert(m_s != INVALID_SOCKET);
	int result = send(m_s, (const char *)buf, bufLen, flags);
	CheckAndHandleError("send", result);
	return result;
}

unsigned int Socket::Receive(byte* buf, unsigned int bufLen, int flags)
{
	assert(m_s != INVALID_SOCKET);
	int result = recv(m_s, (char *)buf, bufLen, flags);
	CheckAndHandleError("recv", result);
	return result;
}

void Socket::IOCtl(long cmd, unsigned long *argp)
{
	assert(m_s != INVALID_SOCKET);
	CheckAndHandleError("listen", ioctlsocket(m_s, cmd, argp));
}

bool Socket::ReadReady(const timeval *timeout)
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(m_s, &fds);
	int ready = select(1, &fds, NULL, NULL, timeout);
	CheckAndHandleError("select", ready);
	return ready > 0;
}

bool Socket::WriteReady(const timeval *timeout)
{
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(m_s, &fds);
	int ready = select(1, NULL, &fds, NULL, timeout);
	CheckAndHandleError("select", ready);
	return ready > 0;
}

void Socket::CheckAndHandleError(const char *operation, SOCKET result) const
{
	if (result == INVALID_SOCKET)
		throw Err(m_s, operation, WSAGetLastError());
}

void Socket::CheckAndHandleError(const char *operation, int result) const
{
	if (result == SOCKET_ERROR)
		throw Err(m_s, operation, WSAGetLastError());
}

SocketSource::SocketSource(SOCKET s, bool pumpAndClose, BufferedTransformation *outQueue, unsigned int maxBufferSize, bool autoSuck)
	: Socket(s), Source(outQueue), m_maxBufferSize(maxBufferSize), m_autoSuck(autoSuck), m_socketClosed(false)
{
	if (pumpAndClose)
	{
		PumpAll();
		MessageEnd();
	}
}

unsigned long SocketSource::GeneralPump(byte delimiter, bool checkDelimiter, unsigned int size, bool checkSize, const timeval *timeout)
{
	if (m_socketClosed)
		return 0;

	unsigned long totalPumpSize = 0;
	bool done = false;

	while (!m_buffer.IsEmpty() && !done)
	{
		byte *p, *block;
		unsigned int contiguousSize;
		block = m_buffer.Spy(contiguousSize);

		if (checkSize && contiguousSize+totalPumpSize > size)
		{
			contiguousSize = (unsigned int)(size-totalPumpSize);
			done = true;
		}

		if (checkDelimiter && (p=std::find(block, block+contiguousSize, delimiter)) != block+contiguousSize)
		{
			AttachedTransformation()->Put(block, p-block);
			m_buffer.Skip(p-block + 1);
			totalPumpSize += p-block;
			done = true;
		}
		else
		{
			AttachedTransformation()->Put(block, contiguousSize);
			m_buffer.Skip(contiguousSize);
			totalPumpSize += contiguousSize;
		}
	}

	if (!done)
	{
		SecByteBlock buf(1024);

		while (!checkSize || totalPumpSize < size)
		{
			bool ready = ReadReady(timeout);
			assert(ready);

			int recvSize;
			if (checkSize)
				recvSize = Receive(buf.ptr, STDMIN((unsigned int)(size-totalPumpSize), buf.size), 0);
			else
				recvSize = Receive(buf.ptr, buf.size, 0);

			if (recvSize == 0)
			{
				m_socketClosed = true;
				break;
			}

			byte *p;
			if (checkDelimiter && (p=std::find(buf.ptr, buf+recvSize, delimiter)) != buf+recvSize)
			{
				AttachedTransformation()->Put(buf, p-buf);
				m_buffer.Put(p+1, buf+recvSize-(p+1));
				totalPumpSize += p-buf;
				break;
			}
			else
			{
				AttachedTransformation()->Put(buf, recvSize);
				totalPumpSize += recvSize;
			}
		}
	}

	if (m_autoSuck)
	{
		timeval zero = {0,0};
		Suck(&zero);
	}

	return totalPumpSize;
}

unsigned int SocketSource::Pump(unsigned int size)
{
	return GeneralPump(0, false, size, true, NULL);
}

unsigned long SocketSource::PumpAll()
{
	return GeneralPump(0, false, 0, false, NULL);
}

unsigned long SocketSource::PumpAll(const timeval *timeout)
{
	return GeneralPump(0, false, 0, false, timeout);
}

unsigned int SocketSource::PumpLine(byte delimiter, unsigned int size)
{
	return GeneralPump(delimiter, true, size, true, NULL);
}

unsigned int SocketSource::Suck(const timeval *timeout)
{
	if (m_socketClosed)
		return 0;

	unsigned int totalSuckSize = 0;

	while (m_buffer.CurrentSize() < m_maxBufferSize)
	{
		if (!ReadReady(timeout))
			break;

		unsigned int contiguousSize = 0;
		byte *block = m_buffer.MakeNewSpace(contiguousSize);

		int recvSize = Receive(block, contiguousSize, 0);

		if (recvSize == 0)
		{
			m_socketClosed = true;
			break;
		}

		m_buffer.OccupyNewSpace(recvSize);
		totalSuckSize += recvSize;
	}

	return totalSuckSize;
}

SocketSink::SocketSink(SOCKET s, unsigned int maxBufferSize, bool autoFlush)
	: Socket(s), m_maxBufferSize(maxBufferSize), m_autoFlush(autoFlush)
{
}

void SocketSink::Put(const byte *str, unsigned int bc)
{
	m_buffer.Put(str, bc);

	while (m_buffer.CurrentSize() > m_maxBufferSize)
	{
		bool ready = WriteReady(NULL);
		assert(ready);

		unsigned int contiguousSize = 0;
		byte *block = m_buffer.Spy(contiguousSize);

		int sentSize = Send(block, contiguousSize, 0);
		m_buffer.Skip(sentSize);
	}

	if (m_autoFlush)
	{
		timeval zero = {0,0};
		Flush(&zero);
	}
}

unsigned int SocketSink::Flush(const timeval *timeout)
{
	unsigned int totalFlushSize = 0;

	while (!m_buffer.IsEmpty())
	{
		if (!WriteReady(timeout))
			break;

		unsigned int contiguousSize = 0;
		byte *block = m_buffer.Spy(contiguousSize);

		int sentSize = Send(block, contiguousSize, 0);
		m_buffer.Skip(sentSize);
		totalFlushSize += sentSize;
	}

	return totalFlushSize;
}

NAMESPACE_END

#endif
