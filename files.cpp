// files.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "files.h"

NAMESPACE_BEGIN(CryptoPP)

static const unsigned int BUFFER_SIZE = 1024;

FileSource::FileSource (std::istream &i, bool pumpAndClose, BufferedTransformation *outQueue)
	: Source(outQueue), in(i)
{
	if (pumpAndClose)
	{
		PumpAll();
		MessageEnd();
	}
}

FileSource::FileSource (const char *filename, bool pumpAndClose, BufferedTransformation *outQueue)
	: Source(outQueue), file(filename, std::ios::in | std::ios::binary), in(file)
{
	if (!file)
		throw OpenErr(filename);

	if (pumpAndClose)
	{
		PumpAll();
		MessageEnd();
	}
}

unsigned int FileSource::Pump(unsigned int size)
{
	unsigned int total=0;
	SecByteBlock buffer(STDMIN(size, BUFFER_SIZE));

	while (size && in.good())
	{
		in.read((char *)buffer.ptr, STDMIN(size, BUFFER_SIZE));
		unsigned l = in.gcount();
		AttachedTransformation()->Put(buffer, l);
		size -= l;
		total += l;
	}

	if (!in.good() && !in.eof())
		throw ReadErr();

	return total;
}

unsigned long FileSource::PumpAll()
{
	unsigned long total=0;
	unsigned int l;

	while ((l=Pump(BUFFER_SIZE)) != 0)
		total += l;

	return total;
}

FileSink::FileSink(std::ostream &o)
	: out(o)
{
}

FileSink::FileSink(const char *filename, bool binary)
	: file(filename, std::ios::out | (binary ? std::ios::binary : std::ios::openmode(0)) | std::ios::trunc), out(file)
{
	if (!file)
		throw OpenErr(filename);
}

void FileSink::Flush(bool, int)
{
	out.flush();
	if (!out.good())
	  throw WriteErr();
}

void FileSink::MessageEnd(int)
{
	Flush(true);
}

void FileSink::Put(const byte *inString, unsigned int length)
{
	out.write((const char *)inString, length);
	if (!out.good())
	  throw WriteErr();
}

NAMESPACE_END
