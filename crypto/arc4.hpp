// arc4.hpp

#ifndef TAO_CRYPT_ARC4_HPP__
#define TAO_CRYPT_ARC4_HPP__

#include "misc.hpp"

namespace TaoCrypt {

class ARC4 {
public:
    enum { STATE_SIZE = 256 };

    typedef ARC4 Encryption;
    typedef ARC4 Decryption;

    void Process(byte*, const byte*, size_t);
    void SetKey(const byte*, size_t);
private:
    byte x_;
    byte y_;
    byte state_[STATE_SIZE];
};

} // namespace


#endif // TAO_CRYPT_ARC4_HPP__

