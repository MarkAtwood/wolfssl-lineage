// gzip.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "gzip.h"

NAMESPACE_BEGIN(CryptoPP)

Gzip::Gzip(int dlevel, BufferedTransformation *bt)
	: Deflator(dlevel, bt),
	  m_totalLen(0)
{
	assert (dlevel >= 1 && dlevel <= 9);
	AttachedTransformation()->Put(MAGIC1);
	AttachedTransformation()->Put(MAGIC2);
	AttachedTransformation()->Put(DEFLATED);
	AttachedTransformation()->Put(0);		// general flag
	AttachedTransformation()->PutWord32(0);	// time stamp
	byte extra = (dlevel == 1) ? FAST : ((dlevel == 9) ? SLOW : 0);
	AttachedTransformation()->Put(extra);
	AttachedTransformation()->Put(GZIP_OS_CODE);
}

void Gzip::Put(byte inByte)
{
	Deflator::Put(inByte);
	m_crc.Update(&inByte, 1);
	++m_totalLen;
}

void Gzip::Put(const byte *inString, unsigned int length)
{
	Deflator::Put(inString, length);
	m_crc.Update(inString, length);
	m_totalLen += length;
}

void Gzip::MessageEnd(int propagation)
{
	Deflator::MessageEnd(0);
	SecByteBlock crc(4);
	m_crc.Final(crc);
	AttachedTransformation()->Put(crc, 4);
	AttachedTransformation()->PutWord32(m_totalLen, false);
	Filter::MessageEnd(propagation);
}

Gunzip::Gunzip(BufferedTransformation *outQueue, bool repeat)
	: Filter(outQueue), m_inflator(new InflatorRedirector(*this))
	, m_repeat(repeat), m_autoSignalPropagation(-1)
{
	m_totalLen = 0;
	m_state = PROCESS_HEADER;
}

void Gunzip::Put(const byte *inString, unsigned int length)
{
	switch (m_state)
	{
		case PROCESS_HEADER:
			m_inQueue.Put(inString, length);
			if (m_inQueue.CurrentSize() >= MAX_HEADERSIZE)
				ProcessHeader();
			break;
		case PROCESS_BODY:
			m_inflator.Put(inString, length);
			break;
		case PROCESS_TAIL:
			m_inQueue.Put(inString, length);
			if (m_inQueue.CurrentSize() >= TAIL_SIZE)
				ProcessTail();
			break;
		case AFTER_END:
			AttachedTransformation()->Put(inString, length);
			break;
	}
}

void Gunzip::MessageEnd(int propagation)
{
	if (m_state == AFTER_END)
		Filter::MessageEnd(propagation);

	if (m_state == PROCESS_HEADER)
		ProcessHeader();

	if (m_state == PROCESS_BODY)
		m_inflator.MessageEnd();

	if (m_state == PROCESS_TAIL)
		ProcessTail();
}

void Gunzip::ProcessHeader()
{
	byte buf[6];
	byte b, flags;

	if (m_inQueue.Get(buf, 2)!=2) goto error;
	if (buf[0] != MAGIC1 || buf[1] != MAGIC2) goto error;
	if (!m_inQueue.Skip(1)) goto error;	 // skip extra flags
	if (!m_inQueue.Get(flags)) goto error;
	if (flags & (ENCRYPTED | CONTINUED)) goto error;
	if (m_inQueue.Skip(6)!=6) goto error;    // Skip file time, extra flags and OS type

	if (flags & EXTRA_FIELDS)	// skip extra fields
	{
		word16 length;
		if(!m_inQueue.GetWord16(length, false)) goto error;
		if (m_inQueue.Skip(length)!=length) goto error;
	}

	if (flags & FILENAME)	// skip filename
		do
			if(!m_inQueue.Get(b)) goto error;
		while (b);

	if (flags & COMMENTS)	// skip comments
		do
			if(!m_inQueue.Get(b)) goto error;
		while (b);

	m_inQueue.TransferTo(m_inflator);
	m_state = PROCESS_BODY;
	return;
error:
	throw HeaderErr();
}

void Gunzip::ProcessTail()
{
	if (m_inQueue.CurrentSize() < TAIL_SIZE)
		throw TailErr();

	SecByteBlock tail(TAIL_SIZE);
	m_inQueue.Get(tail, TAIL_SIZE);

	if (!m_crc.Verify(tail))
		throw CrcErr();

	if ((((word32)tail[4]) | ((word32)tail[5] << 8) | ((word32)tail[6] << 16) | ((word32)tail[7] << 24)) != m_totalLen)
		throw LengthErr();

	Filter::MessageEnd(m_autoSignalPropagation);

	if (m_repeat)
	{
		m_totalLen = 0;
		m_state = PROCESS_HEADER;
		m_inflator.Reset();
	}
	else
	{
		m_state = AFTER_END;
		m_inQueue.TransferTo(*AttachedTransformation());
	}
}

void Gunzip::InflatorRedirector::Put(const byte *inString, unsigned int length)
{
	if (parent.m_state == PROCESS_BODY)
	{
		parent.AttachedTransformation()->Put(inString, length);
		parent.m_crc.Update(inString, length);
		parent.m_totalLen += length;
	}
	else
		parent.Put(inString, length);
}

void Gunzip::InflatorRedirector::MessageEnd(int)
{
	parent.m_state = PROCESS_TAIL;
}

NAMESPACE_END
