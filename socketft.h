#ifndef CRYPTOPP_SOCKETFT_H
#define CRYPTOPP_SOCKETFT_H

#ifdef _MSC_VER		// TODO: port to other compilers/OS

#include "filters.h"
#include "queue.h"
#include <winsock.h>

NAMESPACE_BEGIN(CryptoPP)

class Socket
{
public:
	class Err : public Exception
	{
	public:
		Err(SOCKET s, const std::string& operation, int error);

		SOCKET GetSocket() const {return m_s;}
		const std::string & GetOperation() const {return m_operation;}
		int GetError() const {return m_error;}

	private:
		SOCKET m_s;
		std::string m_operation;
		int m_error;
	};

	Socket(SOCKET s = INVALID_SOCKET, bool own=false) : m_s(s), m_own(own) {}
	Socket(const Socket &s) : m_s(s.m_s), m_own(false) {}
	virtual ~Socket();

	SOCKET GetSocket() {return m_s;}
	void AttachSocket(SOCKET s, bool own=false);
	SOCKET DetachSocket();

	void Create(int nType = SOCK_STREAM);
	void Close();
	void Bind(unsigned int port, const char *addr=NULL);
	void Bind(const sockaddr* psa, unsigned int saLen);
	void Listen(int backlog=5);
	void Connect(const char *addr, unsigned int port);
	void Connect(const sockaddr* psa, int saLen);
	bool Accept(Socket& s, sockaddr *psa=NULL, int *psaLen=NULL);
	unsigned int Send(const byte* buf, unsigned int bufLen, int flags=0);
	unsigned int Receive(byte* buf, unsigned int bufLen, int flags=0);

	void IOCtl(long cmd, unsigned long *argp);
	bool ReadReady(const timeval *timeout);
	bool WriteReady(const timeval *timeout);

protected:
	virtual void SocketChanged() {}
	virtual void CheckAndHandleError(const char *operation, SOCKET result) const;
	virtual void CheckAndHandleError(const char *operation, int result) const;

	SOCKET m_s;
	bool m_own;
};

class SocketSource : public Socket, public Source
{
public:
	SocketSource(SOCKET s, bool pumpAndClose, BufferedTransformation *outQueue = NULL, unsigned int maxBufferSize=0, bool autoSuck=false);

	unsigned long GeneralPump(byte delimiter, bool checkDelimiter, unsigned int size, bool checkSize, const timeval *timeout);

	unsigned int Pump(unsigned int size);
	unsigned long PumpAll();

	unsigned long PumpAll(const timeval *timeout);
	unsigned int PumpLine(byte delimiter='\n', unsigned int size=1024);

	unsigned int Suck(const timeval *timeout);

	void SetMaxBufferSize(unsigned int maxBufferSize) {m_maxBufferSize = maxBufferSize;}
	void SetAutoSuck(bool autoSuck = true) {m_autoSuck = autoSuck;}

	unsigned int GetCurrentBufferSize() const {return m_buffer.CurrentSize();}

private:

	unsigned int m_maxBufferSize;
	bool m_autoSuck, m_socketClosed;
	ByteQueue m_buffer;
};

class SocketSink : public Socket, public Sink
{
public:
	SocketSink(SOCKET s, unsigned int maxBufferSize=0, bool autoFlush=false);

	void Put(byte b) {SocketSink::Put(&b, 1);}
	void Put(const byte *str, unsigned int bc);

	// TODO add Flush and fix MessageEnd
	void MessageEnd(int) {}

	void Write(const char *str) {Put((byte *)str, strlen(str));}

	unsigned int Flush(const timeval *timeout);

	void SetMaxBufferSize(unsigned int maxBufferSize) {m_maxBufferSize = maxBufferSize;}
	void SetAutoFlush(bool autoFlush = true) {m_autoFlush = autoFlush;}

	unsigned int GetCurrentBufferSize() const {return m_buffer.CurrentSize();}

private:
	unsigned int m_maxBufferSize;
	bool m_autoFlush;
	ByteQueue m_buffer;
};

NAMESPACE_END

#endif

#endif
