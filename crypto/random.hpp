// random.hpp
#ifndef TAO_CRYPT_RANDOM_HPP__
#define TAO_CRYPT_RANDOM_HPP__

#include "misc.hpp"

namespace TaoCrypt {



class RandomNumberGenerator {
public:
    RandomNumberGenerator();
    ~RandomNumberGenerator() {}

    void GenerateBlock(byte*, size_t sz);
    byte GenerateByte();

    RandomNumberGenerator& Ref() { return *this; }
};





}  // namespace

#endif // TAO_CRYPT_RANDOM_HPP__

