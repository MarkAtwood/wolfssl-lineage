// rsa.cpp

#include "rsa.hpp"
#include "asn.hpp"
#include "modarith.hpp"
#include <stdexcept>

namespace TaoCrypt {


Integer RSA_PublicKey::ApplyFunction(const Integer& x) const
{
	return a_exp_b_mod_c(x, e_, n_);
}



Integer RSA_PrivateKey::CalculateInverse(RandomNumberGenerator& rng,
                                         const Integer& x) const
{
	ModularArithmetic modn(n_);
	
    Integer r(rng, Integer::One(), n_ - Integer::One());
	Integer re = modn.Exponentiate(r, e_);
	re = modn.Multiply(re, x);			// blind
	// here we follow the notation of PKCS #1 and let u=q inverse mod p
	// but in ModRoot, u=p inverse mod q, so we reverse the order of p and q
	Integer y = ModularRoot(re, dq_, dp_, q_, p_, u_);
	y = modn.Divide(y, r);				// unblind
	if (modn.Exponentiate(y, e_) != x)		// check
        throw std::runtime_error("error during priv key operation");
	return y;
}


void RSA_PrivateKey::Initialize(RSA_Private_Decoder& decoder)
{
    decoder.Decode(*this);
}


void RSA_BlockType2::Pad(const byte *input, size_t inputLen, byte *pkcsBlock,
                         size_t pkcsBlockLen, RandomNumberGenerator& rng) const
{
	// convert from bit length to byte length
	if (pkcsBlockLen % 8 != 0)
	{
		pkcsBlock[0] = 0;
		pkcsBlock++;
	}
	pkcsBlockLen /= 8;

	pkcsBlock[0] = 2;  // block type 2

	// pad with non-zero random bytes
    for (unsigned i = 1; i < pkcsBlockLen-inputLen-1; i++) {
        pkcsBlock[i] = rng.GenerateByte();
        if (pkcsBlock[i] == 0) pkcsBlock[i] = 0x01;
    }

	pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     // separator
	memcpy(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);
}

size_t RSA_BlockType2::UnPad(const byte *pkcsBlock, unsigned int pkcsBlockLen,
                           byte *output) const
{
	bool invalid = false;
	unsigned int maxOutputLen = SaturatingSubtract(pkcsBlockLen / 8, 10U);

	// convert from bit length to byte length
	if (pkcsBlockLen % 8 != 0)
	{
		invalid = (pkcsBlock[0] != 0) || invalid;
		pkcsBlock++;
	}
	pkcsBlockLen /= 8;

	// Require block type 2.
	invalid = (pkcsBlock[0] != 2) || invalid;

	// skip past the padding until we find the separator
	unsigned i=1;
	while (i<pkcsBlockLen && pkcsBlock[i++]) { // null body
		}
	assert(i==pkcsBlockLen || pkcsBlock[i-1]==0);

	unsigned int outputLen = pkcsBlockLen - i;
	invalid = (outputLen > maxOutputLen) || invalid;

	if (invalid)
        throw std::runtime_error("invalid block type 2 unpad");

	memcpy (output, pkcsBlock+i, outputLen);
    return outputLen;
}


void RSA_BlockType1::Pad(const byte* input, size_t inputLen, byte* pkcsBlock,
                         size_t pkcsBlockLen, RandomNumberGenerator&) const
{
    // convert from bit length to byte length
    if (pkcsBlockLen % 8 != 0)
    {
        pkcsBlock[0] = 0;
        pkcsBlock++;
    }
    pkcsBlockLen /= 8;

    pkcsBlock[0] = 1;  // block type 1 for SSL

    // pad with 0xff bytes
    memset(&pkcsBlock[1], 0xFF, pkcsBlockLen - inputLen - 2);

    pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     // separator
    memcpy(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);
}


size_t RSA_BlockType1::UnPad(const byte* pkcsBlock, size_t pkcsBlockLen,
                             byte* output) const
{
    bool invalid = false;
    unsigned int maxOutputLen = SaturatingSubtract(pkcsBlockLen / 8, 10U);

    // convert from bit length to byte length
    if (pkcsBlockLen % 8 != 0)
    {
        invalid = (pkcsBlock[0] != 0) || invalid;
        pkcsBlock++;
    }
    pkcsBlockLen /= 8;

    // Require block type 1 for SSL.
    invalid = (pkcsBlock[0] != 1) || invalid;

    // skip past the padding until we find the separator
    unsigned i=1;
    while (i<pkcsBlockLen && pkcsBlock[i++]) { // null body
		}
    assert(i==pkcsBlockLen || pkcsBlock[i-1]==0);

    unsigned int outputLen = pkcsBlockLen - i;
    invalid = (outputLen > maxOutputLen) || invalid;

    if (invalid)
        return 0;

    memcpy(output, pkcsBlock+i, outputLen);
    return outputLen;
}


void SSL_Decrypt(RSA_PublicKey& key, const byte* sig, size_t sz, byte* plain)
{
    PK_Lengths lengths(key.GetModulus());
   
    ByteBlock paddedBlock(BitsToBytes(lengths.PaddedBlockBitLength()));
    Integer x = key.ApplyFunction(Integer(sig, lengths.FixedCiphertextLength()));

    if (x.ByteCount() > paddedBlock.size())
        x = Integer::Zero();	
    x.Encode(paddedBlock.get_buffer(), paddedBlock.size());
    RSA_BlockType1().UnPad(paddedBlock.get_buffer(),
                           lengths.PaddedBlockBitLength(), plain);
}


} // namespace
