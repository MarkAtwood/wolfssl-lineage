// file.cpp

#include "file.hpp"

namespace TaoCrypt {

byte* reallocate(byte *p, size_t oldSize, size_t newSize, bool preserve)
{
	if (oldSize == newSize)
		return p;

	if (preserve) {
		byte* newPointer = new byte[newSize];
        memcpy(newPointer, p, min(oldSize, newSize));
		delete[] p;
		return newPointer;
	}
	else {
		delete[] p;
		return new byte[newSize];
	}
}


size_t FileSource::size(bool use_current)
{
    using std::streampos;

    streampos current = file_.tellg();
    streampos begin;
    if (use_current)
        begin = current;
    else
        begin = file_.seekg(0, std::ios::beg).tellg();
    streampos end = file_.seekg(0, std::ios::end).tellg();

	file_.seekg(current);

	return end - begin;
}


size_t FileSource::size_left()
{
    return size(true);
}


size_t FileSource::get(Sink& sink)
{
    size_t sz = size();
    if (sink.size() < sz)
        sink.set_size(sz);

    file_.read(reinterpret_cast<char*>(sink.get_buffer()), sz);

    return sz;
}


}  // namespace
