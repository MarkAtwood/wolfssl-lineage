#ifndef CRYPTOPP_FILTERS_H
#define CRYPTOPP_FILTERS_H

#include "cryptlib.h"
#include "misc.h"
#include "smartptr.h"
#include "queue.h"

NAMESPACE_BEGIN(CryptoPP)

// Filter provides an implementation of BufferedTransformation's
// attachment interface

class Filter : virtual public BufferedTransformation
{
public:
	Filter(BufferedTransformation *outQ);

	bool Attachable() {return true;}
	BufferedTransformation *AttachedTransformation() {return m_outQueue.get();}
	const BufferedTransformation *AttachedTransformation() const {return m_outQueue.get();}
	void Detach(BufferedTransformation *newOut = NULL);

protected:
	virtual void NotifyAttachmentChange() {}
	void Insert(Filter *nextFilter);	// insert filter after this one

private:
	void operator=(const Filter &); // assignment not allowed

	member_ptr<BufferedTransformation> m_outQueue;
};

class TransparentFilter : public Filter
{
public:
	TransparentFilter(BufferedTransformation *outQ=NULL) : Filter(outQ) {}
	void Put(byte inByte) {BufferedTransformation::Put(inByte);}
	void Put(const byte *inString, unsigned int length) {BufferedTransformation::Put(inString, length);}
};

class OpaqueFilter : public Filter
{
public:
	OpaqueFilter(BufferedTransformation *outQ=NULL) : Filter(outQ) {}
	void Put(byte inByte) {}
	void Put(const byte *inString, unsigned int length) {}
};

// FilterWithBufferedInput divides up the input stream into
// a first block, a number of middle blocks, and a last block.
// First and last blocks are optional, and middle blocks may
// be a stream instead (i.e. blockSize == 1).

class FilterWithBufferedInput : public Filter
{
public:
	// firstSize and lastSize may be 0, blockSize must be at least 1
	FilterWithBufferedInput(unsigned int firstSize, unsigned int blockSize, unsigned int lastSize, BufferedTransformation *outQ);
	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	void MessageEnd(int propagation=-1);

	// the input buffer may contain more than blockSize bytes if lastSize != 0
	// ForceNextPut() forces a call to NextPut() if this is the case
	void ForceNextPut();

protected:
	bool DidFirstPut() {return m_firstInputDone;}

	// FirstPut() is called if (firstSize != 0 and totalLength >= firstSize)
	// or (firstSize == 0 and (totalLength > 0 or a MessageEnd() is received))
	virtual void FirstPut(const byte *inString) =0;
	// NextPut() is called if totalLength >= firstSize+blockSize+lastSize
	// length parameter is always blockSize unless blockSize == 1
	virtual void NextPut(const byte *inString, unsigned int length) =0;
	// LastPut() is always called
	// if totalLength < firstSize then length == totalLength
	// else if totalLength <= firstSize+lastSize then length == totalLength-firstSize
	// else lastSize <= length < lastSize+blockSize
	virtual void LastPut(const byte *inString, unsigned int length) =0;

private:
	class BlockQueue
	{
	public:
		BlockQueue(unsigned int blockSize, unsigned int maxBlocks);
		void ResetQueue(unsigned int blockSize, unsigned int maxBlocks);
		const byte *GetBlock();
		const byte *GetContigousBlocks(unsigned int &numberOfBlocks);
		unsigned int GetAll(byte *outString);
		void Put(const byte *inString, unsigned int length);
		unsigned int CurrentSize() const {return m_size;}
		unsigned int MaxSize() const {return m_buffer.size;}

	private:
		SecByteBlock m_buffer;
		unsigned int m_blockSize, m_maxBlocks, m_size;
		byte *m_begin;
	};

	unsigned int m_firstSize, m_blockSize, m_lastSize;
	bool m_firstInputDone;
	BlockQueue m_queue;
};

class FilterWithInputQueue : public Filter
{
public:
	FilterWithInputQueue(BufferedTransformation *attachment) : Filter(attachment) {}
	void Put(byte inByte) {m_inQueue.Put(inByte);}
	void Put(const byte *inString, unsigned int length) {m_inQueue.Put(inString, length);}

protected:
	ByteQueue m_inQueue;
};

class StreamCipherFilter : public Filter
{
public:
	StreamCipherFilter(StreamCipher &c,
					   BufferedTransformation *outQueue = NULL)
		: cipher(c), Filter(outQueue) {}

	void Put(byte inByte)
		{AttachedTransformation()->Put(cipher.ProcessByte(inByte));}

	void Put(const byte *inString, unsigned int length);

private:
	StreamCipher &cipher;
};

class HashFilter : public Filter
{
public:
	HashFilter(HashModule &hm, BufferedTransformation *outQueue = NULL, bool putMessage=false)
		: Filter(outQueue), m_hashModule(hm), m_putMessage(putMessage) {}

	void MessageEnd(int propagation=-1);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);

private:
	HashModule &m_hashModule;
	bool m_putMessage;
};

class HashVerifier : public FilterWithBufferedInput
{
public:
	class HashVerificationFailed : public BufferedTransformation::Err
	{
	public:
		HashVerificationFailed()
			: BufferedTransformation::Err(DATA_INTEGRITY_CHECK_FAILED, "HashVerifier: message hash not correct") {}
	};

	enum Flags {HASH_AT_BEGIN=1, PUT_MESSAGE=2, PUT_HASH=4, PUT_RESULT=8, THROW_EXCEPTION=16};
	HashVerifier(HashModule &hm, BufferedTransformation *outQueue = NULL, word32 flags = HASH_AT_BEGIN | PUT_RESULT);

	bool GetLastResult() const {return m_verified;}

protected:
	void FirstPut(const byte *inString);
	void NextPut(const byte *inString, unsigned int length);
	void LastPut(const byte *inString, unsigned int length);

private:
	HashModule &m_hashModule;
	word32 m_flags;
	SecByteBlock m_expectedHash;
	bool m_verified;
};

class SignerFilter : public Filter
{
public:
	SignerFilter(RandomNumberGenerator &rng, const PK_Signer &signer, BufferedTransformation *outQueue = NULL)
		: rng(rng), signer(signer), messageAccumulator(signer.NewMessageAccumulator()), Filter(outQueue) {}

	void MessageEnd(int propagation);

	void Put(byte inByte)
		{messageAccumulator->Update(&inByte, 1);}

	void Put(const byte *inString, unsigned int length)
		{messageAccumulator->Update(inString, length);}

private:
	RandomNumberGenerator &rng;
	const PK_Signer &signer;
	member_ptr<HashModule> messageAccumulator;
};

class VerifierFilter : public Filter
{
public:
	VerifierFilter(const PK_Verifier &verifier, BufferedTransformation *outQueue = NULL)
		: verifier(verifier), messageAccumulator(verifier.NewMessageAccumulator())
		, signature(verifier.SignatureLength()), Filter(outQueue) {}

	// this function must be called before MessageEnd()
	void PutSignature(const byte *sig);

	void MessageEnd(int propagation);

	void Put(byte inByte)
		{messageAccumulator->Update(&inByte, 1);}

	void Put(const byte *inString, unsigned int length)
		{messageAccumulator->Update(inString, length);}

private:
	const PK_Verifier &verifier;
	member_ptr<HashModule> messageAccumulator;
	SecByteBlock signature;
};

class Source : public Filter
{
public:
	Source(BufferedTransformation *outQ)
		: Filter(outQ) {}

	void Put(byte)
		{Pump(1);}
	void Put(const byte *, unsigned int length)
		{Pump(length);}
	void MessageEnd(int propagation=-1)
		{PumpAll(); Filter::MessageEnd(propagation);}

	virtual unsigned int Pump(unsigned int pumpMax) =0;
	virtual unsigned long PumpAll() =0;
};

class StringSource : public Source
{
public:
	StringSource(const char *source, bool pumpAndClose, BufferedTransformation *outQueue = NULL);
	StringSource(const byte *source, unsigned int length, bool pumpAndClose, BufferedTransformation *outQueue = NULL);
	StringSource(const std::string &source, bool pumpAndClose, BufferedTransformation *outQueue = NULL);

	unsigned int Pump(unsigned int size);
	unsigned long PumpAll();

private:
	const byte *m_source;
	unsigned int m_length, m_count;
};

class Sink : public BufferedTransformation
{
};

class BitBucket : public Sink
{
public:
	void Put(byte) {}
	void Put(const byte *, unsigned int) {}
};

class Redirector : public Sink
{
public:
	Redirector(BufferedTransformation *target, bool passSignal=true) : m_target(target), m_passSignal(passSignal) {}
	void Redirect(BufferedTransformation *target) {m_target = target;}
	void SetPassSignal(bool passSignal) {m_passSignal = passSignal;}
	void Put(byte b) 
		{if (m_target) m_target->Put(b);}
	void Put(const byte *string, unsigned int len) 
		{if (m_target) m_target->Put(string, len);}
	void Flush(bool completeFlush, int propagation=-1) 
		{if (m_target && m_passSignal) m_target->Flush(completeFlush, propagation);}
	void MessageEnd(int propagation=-1)
		{if (m_target && m_passSignal) m_target->MessageEnd(propagation);}
	void MessageSeriesEnd(int propagation=-1) 
		{if (m_target && m_passSignal) m_target->MessageSeriesEnd(propagation);}

private:
	BufferedTransformation *m_target;
	bool m_passSignal;
};

class OutputProxy : public Sink
{
public:
	OutputProxy(BufferedTransformation &parent, bool passSignal=true) : m_parent(parent), m_passSignal(passSignal) {}
	void SetPassSignal(bool passSignal) {m_passSignal = passSignal;}
	void Put(byte b) 
		{m_parent.BufferedTransformation::Put(b);}
	void Put(const byte *string, unsigned int len) 
		{m_parent.BufferedTransformation::Put(string, len);}
	void Flush(bool completeFlush, int propagation=-1) 
		{if (m_passSignal) m_parent.BufferedTransformation::Flush(completeFlush, propagation);}
	void MessageEnd(int propagation=-1)
		{if (m_passSignal) m_parent.BufferedTransformation::MessageEnd(propagation);}
	void MessageSeriesEnd(int propagation=-1) 
		{if (m_passSignal) m_parent.BufferedTransformation::MessageSeriesEnd(propagation);}

private:
	BufferedTransformation &m_parent;
	bool m_passSignal;
};

class ProxyFilter : public FilterWithBufferedInput
{
public:
	ProxyFilter(Filter *filter, unsigned int firstSize, unsigned int lastSize, BufferedTransformation *outQ);

	void SetFilter(Filter *filter);
	void NextPut(const byte *s, unsigned int len);

protected:
	member_ptr<Filter> m_filter;
	OutputProxy *m_proxy;
};

class StringSink : public Sink
{
public:
	StringSink(std::string &output)
		: m_output(output) {}
	void Put(byte b)
		{m_output += b;}
	void Put(const byte *str, unsigned int bc)
		{m_output.append((const char *)str, bc);}

private:	
	std::string &m_output;
};

class Store : public BufferedTransformation
{
public:
	void Put(byte)
		{}
	void Put(const byte *, unsigned int length)
		{}
};

class StringStore : public Store
{
public:
	StringStore(const char *store)
		: m_store((const byte *)store), m_length(strlen(store)), m_count(0) {}
	StringStore(const byte *store, unsigned int length)
		: m_store(store), m_length(length), m_count(0) {}

	unsigned long MaxRetrievable() const;

	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);

	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;

	unsigned long CopyTo(BufferedTransformation &target) const;
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const;

private:
	const byte *m_store;
	unsigned int m_length, m_count;
};

/*
BufferedTransformation *Insert(const byte *in, unsigned int length, BufferedTransformation *outQueue);
unsigned int Extract(Source *source, byte *out, unsigned int length);
*/

NAMESPACE_END

#endif
