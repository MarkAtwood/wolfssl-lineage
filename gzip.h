#ifndef CRYPTOPP_GZIP_H
#define CRYPTOPP_GZIP_H

#include "zdeflate.h"
#include "zinflate.h"
#include "crc.h"

NAMESPACE_BEGIN(CryptoPP)

class Gzip : public Deflator
{
public:
	Gzip(int deflate_level, BufferedTransformation *bt = NULL);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	void MessageEnd(int propagate=-1);

protected:
	enum {MAGIC1=0x1f, MAGIC2=0x8b,   // flags for the header
		  DEFLATED=8, FAST=4, SLOW=2};

	unsigned long m_totalLen;
	CRC32 m_crc;
};

class Gunzip : public Filter
{
public:
	class Err : public BufferedTransformation::Err 
	{
	public:
		Err(ErrorType errorType, const std::string &s) 
			: BufferedTransformation::Err(errorType, s) {}
	};

	class HeaderErr : public Err {public: HeaderErr() : Err(INVALID_DATA_FORMAT, "Gunzip: header decoding error") {}};
	class TailErr : public Err {public: TailErr() : Err(INVALID_DATA_FORMAT, "Gunzip: tail too short") {}};
	class CrcErr : public Err {public: CrcErr() : Err(DATA_INTEGRITY_CHECK_FAILED, "Gunzip: CRC check error") {}};
	class LengthErr : public Err {public: LengthErr() : Err(DATA_INTEGRITY_CHECK_FAILED, "Gunzip: length check error") {}};

	Gunzip(BufferedTransformation *outQueue = NULL, bool repeat = false);

	void Put(byte inByte) {Put(&inByte, 1);}
	void Put(const byte *inString, unsigned int length);
	void MessageEnd(int propagate=-1);
	void SetAutoSignalPropagation(int propagation) {m_autoSignalPropagation = propagation;}

protected:
	enum {MAGIC1=0x1f, MAGIC2=0x8b,   // flags for the header
		  DEFLATED=8,
		  MAX_HEADERSIZE=1024, TAIL_SIZE=8};

	enum FLAG_MASKS {
		CONTINUED=2, EXTRA_FIELDS=4, FILENAME=8, COMMENTS=16, ENCRYPTED=32};

	class InflatorRedirector : public Sink
	{
	public:
		InflatorRedirector(Gunzip &parent) : parent(parent) {}
		void Put(byte inByte) {Put(&inByte, 1);}
		void Put(const byte *inString, unsigned int length);
		void MessageEnd(int);
	private:
		Gunzip &parent;
	};

	friend class InflatorRedirector;

	void ProcessHeader();
	void ProcessTail();

	Inflator m_inflator;
	ByteQueue m_inQueue;

	unsigned long m_totalLen;
	CRC32 m_crc;

	enum State {PROCESS_HEADER, PROCESS_BODY, PROCESS_TAIL, AFTER_END};
	State m_state;

	bool m_repeat;
	int m_autoSignalPropagation;
};

NAMESPACE_END

#endif
