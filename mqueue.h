#ifndef CRYPTOPP_MQUEUE_H
#define CRYPTOPP_MQUEUE_H

#include "queue.h"
#include <list>

NAMESPACE_BEGIN(CryptoPP)

class MessageQueue : public BufferedTransformation
{
public:
	MessageQueue(unsigned int nodeSize=256);

	ByteQueue & Head() {return m_qv.front();}
	const ByteQueue & Head() const {return m_qv.front();}
	ByteQueue & Tail() {return m_qv.back();}
	const ByteQueue & Tail() const {return m_qv.back();}

	void Put(byte inByte)
		{Tail().Put(inByte);}
	void Put(const byte *inString, unsigned int length)
		{Tail().Put(inString, length);}

	unsigned long MaxRetrievable() const
		{return Head().MaxRetrievable();}
	bool AnyRetrievable() const
		{return Head().AnyRetrievable();}

	unsigned int Get(byte &outByte)
		{return Head().Get(outByte);}
	unsigned int Get(byte *outString, unsigned int getMax)
		{return Head().Get(outString, getMax);}

	unsigned long TransferTo(BufferedTransformation &target)
		{return Head().TransferTo(target);}
	unsigned int TransferTo(BufferedTransformation &target, unsigned int transferMax)
		{return Head().TransferTo(target, transferMax);}

	unsigned int Skip(unsigned int skipMax)
		{return Head().Skip(skipMax);}

	unsigned int Peek(byte &outByte) const
		{return Head().Peek(outByte);}
	unsigned int Peek(byte *outString, unsigned int peekMax) const
		{return Head().Peek(outString, peekMax);}

	unsigned long CopyTo(BufferedTransformation &target) const
		{return Head().CopyTo(target);}
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const
		{return Head().CopyTo(target, copyMax);}

	void MessageEnd(int propagate=-1);
	void SetAutoSignalPropagation(int propagation) {m_autoSignalPropagation = propagation;}

	unsigned long TotalBytesRetrievable() const;
	unsigned int NumberOfMessages() const;
	bool CurrentMessageIsComplete() const;
	bool RetrieveNextMessage();
	unsigned int SkipMessages();
	unsigned int SkipMessages(unsigned int count);
	unsigned int TransferMessagesTo(BufferedTransformation &target);
	unsigned int TransferMessagesTo(BufferedTransformation &target, unsigned int count);
	unsigned int CopyMessagesTo(BufferedTransformation &target) const;
	unsigned int CopyMessagesTo(BufferedTransformation &target, unsigned int count) const;

private:
	int m_autoSignalPropagation;
	unsigned int m_nodeSize;
	std::list<ByteQueue> m_qv;
};

NAMESPACE_END

#endif
