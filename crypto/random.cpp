// random.cpp

#include "random.hpp"
#include <ctime>

namespace TaoCrypt {


RandomNumberGenerator::RandomNumberGenerator()
{
    srand(time(0));
}


void RandomNumberGenerator::GenerateBlock(byte* output, size_t sz)
{
    size_t i(0);
    while (sz--) output[i++] = GenerateByte();
}


byte RandomNumberGenerator::GenerateByte()
{
    int i = rand();
    return byte(i % 256);
}


} // namespace
