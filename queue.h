// specification file for an unlimited queue for storing bytes

#ifndef CRYPTOPP_QUEUE_H
#define CRYPTOPP_QUEUE_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

// The queue is implemented as a linked list of arrays, but you don't need to
// know about that.  So just ignore this next line. :)
class ByteQueueNode;

class ByteQueue : public BufferedTransformation
{
public:
	ByteQueue(unsigned int nodeSize=256);
	ByteQueue(const ByteQueue &copy);
	~ByteQueue();

	unsigned long MaxRetrievable() const
		{return CurrentSize();}
	bool AnyRetrievable() const
		{return !IsEmpty();}

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);

	void MessageEnd(int) {}

	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);

	unsigned long TransferTo(BufferedTransformation &target);
	unsigned int TransferTo(BufferedTransformation &target, unsigned int transferMax);

	unsigned long Skip();
	unsigned int Skip(unsigned int skipMax);

	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;

	unsigned long CopyTo(BufferedTransformation &target) const;
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const;

	unsigned long TotalBytesRetrievable() const
		{return CurrentSize();}
	unsigned int NumberOfMessages() const
		{return IsEmpty() ? 0 : 1;}
	bool CurrentMessageIsComplete() const
		{return false;}
	bool RetrieveNextMessage()
		{return false;}
	unsigned int SkipMessages()
		{return IsEmpty() ? 0 : (Clear(), 1);}
	unsigned int SkipMessages(unsigned int count)
		{return IsEmpty() || !count ? 0 : (Clear(), 1);}
	unsigned int TransferMessagesTo(BufferedTransformation &target)
		{return IsEmpty() ? 0 : (TransferTo(target), 1);}
	unsigned int TransferMessagesTo(BufferedTransformation &target, unsigned int count)
		{return IsEmpty() || !count ? 0 : (TransferTo(target, count), 1);}
	unsigned int CopyMessagesTo(BufferedTransformation &target) const
		{return IsEmpty() ? 0 : (CopyTo(target), 1);}
	unsigned int CopyMessagesTo(BufferedTransformation &target, unsigned int count) const
		{return IsEmpty() || !count ? 0 : (CopyTo(target, count), 1);}

	// these member functions are not inherited
	unsigned long CurrentSize() const;
	bool IsEmpty() const;

	void Clear();

	byte * Spy(unsigned int &contiguousSize);
	const byte * Spy(unsigned int &contiguousSize) const;

	byte * MakeNewSpace(unsigned int &contiguousSize);
	void OccupyNewSpace(unsigned int size);

	// TODO: implement LazyPut
	void LazyPut(const byte *inString, unsigned int size) {Put(inString, size);}
	void FinalizeLazyPut() {}

	ByteQueue & operator=(const ByteQueue &rhs);
	bool operator==(const ByteQueue &rhs) const;
	byte operator[](unsigned long i) const;

private:
	void CleanupUsedNodes();
	void CopyFrom(const ByteQueue &copy);
	void Destroy();

	unsigned int nodeSize;
	ByteQueueNode *head, *tail;
};

// use this to make sure LazyPut is finalized in event of exception
class LazyPutter
{
public:
	LazyPutter(ByteQueue &bq, const byte *inString, unsigned int size)
		: m_bq(bq) {bq.LazyPut(inString, size);}
	~LazyPutter()
		{try {m_bq.FinalizeLazyPut();} catch(...) {}}
private:
	ByteQueue &m_bq;
};

NAMESPACE_END

#endif
