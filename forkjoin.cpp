// forkjoin.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "forkjoin.h"
#include "queue.h"
#include <memory>

NAMESPACE_BEGIN(CryptoPP)

Fork::Fork(unsigned int n, BufferedTransformation *const *givenOutPorts)
	: numberOfPorts(n), outPorts(n)
{
	currentPort = 0;

	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i].reset(givenOutPorts ? givenOutPorts[i] : new ByteQueue);
}

Fork::Fork(BufferedTransformation *outport0, BufferedTransformation *outport1)
	: numberOfPorts(2), outPorts(2)
{
	currentPort = 0;
	outPorts[0].reset(outport0 ? outport0 : new ByteQueue);
	outPorts[1].reset(outport1 ? outport1 : new ByteQueue);
}

void Fork::SelectOutPort(unsigned int portNumber)
{
	currentPort = portNumber;
}

void Fork::Detach(BufferedTransformation *newOut)
{
	outPorts[currentPort].reset(newOut ? newOut : new ByteQueue);
}

void Fork::MessageEnd(int propagation)
{
	if (propagation)
		for (unsigned int i=0; i<numberOfPorts; i++)
			outPorts[i]->MessageEnd(propagation-1);
}

void Fork::MessageSeriesEnd(int propagation)
{
	if (propagation)
		for (unsigned int i=0; i<numberOfPorts; i++)
			outPorts[i]->MessageSeriesEnd(propagation);
}

void Fork::Put(byte inByte)
{
	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i]->Put(inByte);
}

void Fork::Put(const byte *inString, unsigned int length)
{
	for (unsigned int i=0; i<numberOfPorts; i++)
		outPorts[i]->Put(inString, length);
}

// ********************************************************

Join::Join(unsigned int n, BufferedTransformation *outQ)
	: Filter(outQ),
	  numberOfPorts(n),
	  inPorts(n),
	  interfacesOpen(n),
	  interfaces(n)
{
	for (unsigned int i=0; i<numberOfPorts; i++)
	{
		inPorts[i].reset(new MessageQueue);
		interfaces[i].reset(new JoinInterface(*this, *inPorts[i], i));
	}
}

JoinInterface * Join::ReleaseInterface(unsigned int i)
{
	return interfaces[i].release();
}

bool Join::AllCurrentMessagesAreComplete() const
{
	for (unsigned int i=0; i<NumberOfPorts(); i++)
		if (!AccessPort(i).CurrentMessageIsComplete())
			return false;
	return true;
}

// ********************************************************

void JoinInterface::Put(byte inByte)
{
	bq.Put(inByte);
	parent.NotifyInput(id, 1);
}

void JoinInterface::Put(const byte *inString, unsigned int length)
{
	bq.Put(inString, length);
	parent.NotifyInput(id, length);
}

unsigned long JoinInterface::MaxRetrievable() const
{
	return parent.MaxRetrievable();
}

void JoinInterface::MessageEnd(int)
{
	parent.NotifyMessageEnd(id);
}

void JoinInterface::MessageSeriesEnd(int) 
{
	parent.NotifyMessageSeriesEnd(id);
}

void JoinInterface::Detach(BufferedTransformation *bt) 
{
	parent.Detach(bt);
}

void JoinInterface::Attach(BufferedTransformation *bt) 
{
	parent.Attach(bt);
}

unsigned int JoinInterface::Get(byte &outByte) 
{
	return parent.Get(outByte);
}

unsigned int JoinInterface::Get(byte *outString, unsigned int getMax)
{
	return parent.Get(outString, getMax);
}

unsigned int JoinInterface::Peek(byte &outByte) const
{
	return parent.Peek(outByte);
}

unsigned int JoinInterface::Peek(byte *outString, unsigned int peekMax) const
{
	return parent.Peek(outString, peekMax);
}

unsigned long JoinInterface::CopyTo(BufferedTransformation &target) const
{
	return parent.CopyTo(target);
}

unsigned int JoinInterface::CopyTo(BufferedTransformation &target, unsigned int copyMax) const
{
	return parent.CopyTo(target, copyMax);
}

NAMESPACE_END
