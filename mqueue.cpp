// mqueue.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "mqueue.h"

NAMESPACE_BEGIN(CryptoPP)

MessageQueue::MessageQueue(unsigned int nodeSize)
	: m_autoSignalPropagation(-1), m_nodeSize(nodeSize), m_qv(1, ByteQueue(nodeSize))
{
}

void MessageQueue::MessageEnd(int)
{
	m_qv.push_back(ByteQueue(m_nodeSize));
}

unsigned long MessageQueue::TotalBytesRetrievable() const
{
	unsigned long total = 0;
	for (std::list<ByteQueue>::const_iterator it = m_qv.begin(); it != m_qv.end(); ++it)
		total += it->CurrentSize();
	return total;
}

unsigned int MessageQueue::NumberOfMessages() const
{
	return m_qv.size()-Tail().IsEmpty();
}

bool MessageQueue::CurrentMessageIsComplete() const
{
	return ++m_qv.begin() != m_qv.end();	// m_qv.size() > 1
}

bool MessageQueue::RetrieveNextMessage()
{
	if (CurrentMessageIsComplete() && Head().IsEmpty())
	{
		m_qv.pop_front();
		return true;
	}
	else
		return false;
}

unsigned int MessageQueue::SkipMessages()
{
	unsigned int i;
	for (i=0; CurrentMessageIsComplete(); ++i)
		m_qv.pop_front();
	if (!Head().IsEmpty())
	{
		Head().Clear();
		i++;
	}
	return i;
}

unsigned int MessageQueue::SkipMessages(unsigned int count)
{
	unsigned int i;
	for (i=0; i<count && CurrentMessageIsComplete(); ++i)
		m_qv.pop_front();
	if (i<count && !Head().IsEmpty())
	{
		Head().Clear();
		i++;
	}
	return i;
}

unsigned int MessageQueue::TransferMessagesTo(BufferedTransformation &target)
{
	unsigned int i;
	for (i=0; CurrentMessageIsComplete(); ++i)
	{
		Head().TransferTo(target);
		if (m_autoSignalPropagation)
			target.MessageEnd(m_autoSignalPropagation-1);
		m_qv.pop_front();
	}
	if (!Head().IsEmpty())
	{
		Head().TransferTo(target);
		i++;
	}
	return i;
}

unsigned int MessageQueue::TransferMessagesTo(BufferedTransformation &target, unsigned int count)
{
	unsigned int i;
	for (i=0; i<count && CurrentMessageIsComplete(); ++i)
	{
		Head().TransferTo(target);
		if (m_autoSignalPropagation)
			target.MessageEnd(m_autoSignalPropagation-1);
		m_qv.pop_front();
	}
	if (i<count && !Head().IsEmpty())
	{
		Head().TransferTo(target);
		i++;
	}
	return i;
}

unsigned int MessageQueue::CopyMessagesTo(BufferedTransformation &target) const
{
	std::list<ByteQueue>::const_iterator it = m_qv.begin();
	std::list<ByteQueue>::const_iterator last = --m_qv.end();
	unsigned int i;
	for (i=0; it != last; ++i, ++it)
	{
		it->CopyTo(target);
		if (m_autoSignalPropagation)
			target.MessageEnd(m_autoSignalPropagation-1);
	}
	if (!it->IsEmpty())
	{
		it->CopyTo(target);
		i++;
	}
	return i;
}

unsigned int MessageQueue::CopyMessagesTo(BufferedTransformation &target, unsigned int count) const
{
	std::list<ByteQueue>::const_iterator it = m_qv.begin();
	std::list<ByteQueue>::const_iterator last = --m_qv.end();
	unsigned int i;
	for (i=0; i<count && it != last; ++i, ++it)
	{
		it->CopyTo(target);
		if (m_autoSignalPropagation)
			target.MessageEnd(m_autoSignalPropagation-1);
	}
	if (i<count && !it->IsEmpty())
	{
		it->CopyTo(target);
		i++;
	}
	return i;
}

NAMESPACE_END
