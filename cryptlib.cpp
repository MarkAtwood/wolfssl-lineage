// cryptlib.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "cryptlib.h"
#include "misc.h"

#include <memory>

NAMESPACE_BEGIN(CryptoPP)

unsigned int RandomNumberGenerator::GenerateBit()
{
	return Parity(GetByte());
}

void RandomNumberGenerator::GenerateBlock(byte *output, unsigned int size)
{
	while (size--)
		*output++ = GetByte();
}

word32 RandomNumberGenerator::GenerateWord32(word32 min, word32 max)
{
	word32 range = max-min;
	const int maxBytes = BytePrecision(range);
	const int maxBits = BitPrecision(range);

	word32 value;

	do
	{
		value = 0;
		for (int i=0; i<maxBytes; i++)
			value = (value << 8) | GetByte();

		value = Crop(value, maxBits);
	} while (value > range);

	return value+min;
}

void StreamCipher::ProcessString(byte *outString, const byte *inString, unsigned int length)
{
	while(length--)
		*outString++ = ProcessByte(*inString++);
}

void StreamCipher::ProcessString(byte *inoutString, unsigned int length)
{
	while(length--)
		*inoutString++ = ProcessByte(*inoutString);
}

bool HashModule::Verify(const byte *digestIn)
{
	SecByteBlock digest(DigestSize());
	Final(digest);
	return memcmp(digest, digestIn, DigestSize()) == 0;
}

BufferedTransformation::Err::Err(ErrorType errorType, const std::string &s)
	: Exception(s), m_errorType(errorType)
{
	if (GetWhat() == "")
	{
		switch (errorType)
		{
		case CANNOT_FLUSH:
			SetWhat("BufferedTransformation: cannot flush buffer");
			break;
		case DATA_INTEGRITY_CHECK_FAILED:
			SetWhat("BufferedTransformation: data integrity check failed");
			break;
		case INVALID_DATA_FORMAT:
			SetWhat("BufferedTransformation: invalid data format");
			break;
		case OUTPUT_ERROR:
			SetWhat("BufferedTransformation: cannot write to output device");
			break;
		case OTHER_ERROR:
			SetWhat("BufferedTransformation: unknown error");
			break;
		default:
			assert(false);
			break;
		}
	}
}

void BufferedTransformation::Put(byte b)
{
	if (AttachedTransformation())
		AttachedTransformation()->Put(b);
}

void BufferedTransformation::Put(const byte *inString, unsigned int length)
{
	if (AttachedTransformation())
		AttachedTransformation()->Put(inString, length);
}

void BufferedTransformation::Flush(bool completeFlush, int propagation)
{
	if (AttachedTransformation() && propagation)
		AttachedTransformation()->Flush(completeFlush, propagation-1);
}

void BufferedTransformation::MessageEnd(int propagation)
{
	if (AttachedTransformation() && propagation)
		AttachedTransformation()->MessageEnd(propagation-1);
}

void BufferedTransformation::MessageSeriesEnd(int propagation)
{
	if (AttachedTransformation() && propagation)
		AttachedTransformation()->MessageSeriesEnd(propagation-1);
}

void BufferedTransformation::PutMessageEnd(const byte *inString, unsigned int length, int propagation)
{
	Put(inString, length);
	MessageEnd(propagation);
}

unsigned long BufferedTransformation::MaxRetrievable() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->MaxRetrievable();
	else
		return 0;
}

bool BufferedTransformation::AnyRetrievable() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->AnyRetrievable();
	else
		return false;
}

unsigned int BufferedTransformation::Get(byte &outByte)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Get(outByte);
	else
		return 0;
}

unsigned int BufferedTransformation::Get(byte *outString, unsigned int getMax)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Get(outString, getMax);
	else
		return 0;
}

unsigned long BufferedTransformation::Skip()
{
	if (AttachedTransformation())
		return AttachedTransformation()->Skip();
	else
		return 0;
}

unsigned int BufferedTransformation::Skip(unsigned int skipMax)
{
	if (AttachedTransformation())
		return AttachedTransformation()->Skip(skipMax);
	else
		return 0;
}

unsigned int BufferedTransformation::Peek(byte &outByte) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->Peek(outByte);
	else
		return 0;
}

unsigned int BufferedTransformation::Peek(byte *outString, unsigned int peekMax) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->Peek(outString, peekMax);
	else
		return 0;
}

unsigned long BufferedTransformation::CopyTo(BufferedTransformation &target) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->CopyTo(target);
	else
		return 0;
}

unsigned int BufferedTransformation::CopyTo(BufferedTransformation &target, unsigned int copyMax) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->CopyTo(target, copyMax);
	else
		return 0;
}

unsigned long BufferedTransformation::TransferTo(BufferedTransformation &target)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferTo(target);
	else
		return 0;
}

unsigned int BufferedTransformation::TransferTo(BufferedTransformation &target, unsigned int size)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferTo(target, size);
	else
		return 0;
}

unsigned long BufferedTransformation::TotalBytesRetrievable() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->TotalBytesRetrievable();
	else
		return 0;
}

unsigned int BufferedTransformation::NumberOfMessages() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->NumberOfMessages();
	else
		return 0;
}

bool BufferedTransformation::CurrentMessageIsComplete() const
{
	if (AttachedTransformation())
		return AttachedTransformation()->CurrentMessageIsComplete();
	else
		return false;
}

bool BufferedTransformation::RetrieveNextMessage()
{
	if (AttachedTransformation())
		return AttachedTransformation()->RetrieveNextMessage();
	else
		return false;
}

unsigned int BufferedTransformation::SkipMessages()
{
	if (AttachedTransformation())
		return AttachedTransformation()->SkipMessages();
	else
		return 0;
}

unsigned int BufferedTransformation::SkipMessages(unsigned int count)
{
	if (AttachedTransformation())
		return AttachedTransformation()->SkipMessages(count);
	else
		return 0;
}

unsigned int BufferedTransformation::TransferMessagesTo(BufferedTransformation &target)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferMessagesTo(target);
	else
		return 0;
}

unsigned int BufferedTransformation::TransferMessagesTo(BufferedTransformation &target, unsigned int count)
{
	if (AttachedTransformation())
		return AttachedTransformation()->TransferMessagesTo(target, count);
	else
		return 0;
}

unsigned int BufferedTransformation::CopyMessagesTo(BufferedTransformation &target) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->CopyMessagesTo(target);
	else
		return 0;
}

unsigned int BufferedTransformation::CopyMessagesTo(BufferedTransformation &target, unsigned int count) const
{
	if (AttachedTransformation())
		return AttachedTransformation()->CopyMessagesTo(target, count);
	else
		return 0;
}

void BufferedTransformation::PutWord16(word16 value, bool highFirst)
{
	if (highFirst)
	{
		Put(value>>8);
		Put(byte(value));
	}
	else
	{
		Put(byte(value));
		Put(value>>8);
	}
}

void BufferedTransformation::PutWord32(word32 value, bool highFirst)
{
	if (highFirst)
	{
		for (int i=0; i<4; i++)
			Put(byte(value>>((3-i)*8)));
	}
	else
	{
		for (int i=0; i<4; i++)
			Put(byte(value>>(i*8)));
	}
}

unsigned int BufferedTransformation::GetWord16(word16 &value, bool highFirst)
{
	if (MaxRetrievable()<2)
		return 0;

	byte buf[2];
	Get(buf, 2);

	if (highFirst)
		value = (buf[0] << 8) | buf[1];
	else
		value = (buf[1] << 8) | buf[0];

	return 2;
}

unsigned int BufferedTransformation::GetWord32(word32 &value, bool highFirst)
{
	if (MaxRetrievable()<4)
		return 0;

	byte buf[4];
	Get(buf, 4);

	if (highFirst)
		value = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf [3];
	else
		value = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf [0];

	return 4;
}

void BufferedTransformation::Attach(BufferedTransformation *newOut)
{
	if (!Attachable())
		return;

	if (AttachedTransformation() && AttachedTransformation()->Attachable())
		AttachedTransformation()->Attach(newOut);
	else
		Detach(newOut);
}

unsigned int PK_FixedLengthCryptoSystem::MaxPlainTextLength(unsigned int cipherTextLength) const
{
	if (cipherTextLength == CipherTextLength())
		return MaxPlainTextLength();
	else
		return 0;
}

unsigned int PK_FixedLengthCryptoSystem::CipherTextLength(unsigned int plainTextLength) const
{
	if (plainTextLength <= MaxPlainTextLength())
		return CipherTextLength();
	else
		return 0;
}

unsigned int PK_FixedLengthDecryptor::Decrypt(const byte *cipherText, unsigned int cipherTextLength, byte *plainText)
{
	if (cipherTextLength != CipherTextLength())
		return 0;

	return Decrypt(cipherText, plainText);
}

void PK_Signer::SignMessage(RandomNumberGenerator &rng, const byte *message, unsigned int messageLen, byte *signature) const
{
	std::auto_ptr<HashModule> accumulator(NewMessageAccumulator());
	accumulator->Update(message, messageLen);
	Sign(rng, accumulator.release(), signature);
}

bool PK_Verifier::VerifyMessage(const byte *message, unsigned int messageLen, const byte *sig) const
{
	std::auto_ptr<HashModule> accumulator(NewMessageAccumulator());
	accumulator->Update(message, messageLen);
	return Verify(accumulator.release(), sig);
}

NAMESPACE_END
