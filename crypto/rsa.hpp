// rsa.hpp

#ifndef TAO_CRYPT_RSA_HPP__
#define TAO_CRYPT_RSA_HPP__

#include "integer.hpp"
#include "random.hpp"
#include <stdexcept>


namespace TaoCrypt {


class RSA_PublicKey {
protected:
    Integer n_;
    Integer e_;
public:
	void Initialize(const Integer& n, const Integer& e) {n_ = n; e_ = e;}

	Integer ApplyFunction(const Integer& x) const;
	Integer PreimageBound() const {return n_;}
	Integer ImageBound() const {return n_;}

	const Integer& GetModulus() const {return n_;}
	const Integer& GetPublicExponent() const {return e_;}

	void SetModulus(const Integer& n) {n_ = n;}
	void SetPublicExponent(const Integer& e) {e_ = e;}
};

class RSA_Private_Decoder;

class RSA_PrivateKey : public RSA_PublicKey {
    Integer d_;
    Integer p_;
    Integer q_;
    Integer dp_;
    Integer dq_;
    Integer u_;
public:
	void Initialize(const Integer& n,  const Integer& e, const Integer& d,
                    const Integer& p,  const Integer& q, const Integer& dp, 
                    const Integer& dq, const Integer& u)
		{n_ = n; e_ = e; d_ = d; p_ = p; q_ = q; dp_ = dp; dq_ = dq; u_ = u;}
    void Initialize(RSA_Private_Decoder& dec);

	Integer CalculateInverse(RandomNumberGenerator&, const Integer&) const;

	const Integer& GetPrime1() const {return p_;}
	const Integer& GetPrime2() const {return q_;}
	const Integer& GetPrivateExponent() const {return d_;}
	const Integer& GetModPrime1PrivateExponent() const {return dp_;}
	const Integer& GetModPrime2PrivateExponent() const {return dq_;}
	const Integer& GetMultiplicativeInverseOfPrime2ModPrime1() const 
                   {return u_;}

	void SetPrime1(const Integer& p) {p_ = p;}
	void SetPrime2(const Integer& q) {q_ = q;}
	void SetPrivateExponent(const Integer& d) {d_ = d;}
	void SetModPrime1PrivateExponent(const Integer& dp) {dp_ = dp;}
	void SetModPrime2PrivateExponent(const Integer& dq) {dq_ = dq;}
	void SetMultiplicativeInverseOfPrime2ModPrime1(const Integer& u) {u_ = u;}
};


class PK_Lengths {
    const Integer& image_;
public:
    explicit PK_Lengths(const Integer& i) : image_(i) {}

	size_t PaddedBlockBitLength()  const {return image_.BitCount() - 1;}
    size_t PaddedBlockByteLength() const 
                {return BitsToBytes(PaddedBlockBitLength());}

	size_t FixedCiphertextLength()   const {return image_.ByteCount();}
	size_t FixedMaxPlaintextLength() const 
                {return SaturatingSubtract(PaddedBlockBitLength() / 8, 10U); }
};



class RSA_BlockType2  {
public:
    void   Pad(const byte*, size_t, byte*, size_t,
               RandomNumberGenerator&) const;
    size_t UnPad(const byte*, size_t, byte*) const;
};


class RSA_BlockType1  {
public:
    void   Pad(const byte*, size_t, byte*, size_t, 
               RandomNumberGenerator&) const;
    size_t UnPad(const byte*, size_t, byte*) const;
};


template<class Pad = RSA_BlockType2>
class RSA_Encryptor {
    RSA_PublicKey& key_;
    Pad            padding_;
public:
    explicit RSA_Encryptor(RSA_PublicKey& k) : key_(k) {}

    void Encrypt(const byte*, size_t, byte*, RandomNumberGenerator&);
    bool SSL_Verify(const byte* msg, size_t sz, const byte* sig);
};


template<class Pad = RSA_BlockType2>
class RSA_Decryptor {
    RSA_PrivateKey& key_;
    Pad             padding_;
public:
    explicit RSA_Decryptor(RSA_PrivateKey& k) : key_(k) {}

    size_t Decrypt(const byte*, size_t, byte*);
    void   SSL_Sign(const byte*, size_t, byte*, RandomNumberGenerator&);
};


template<class Pad>
void RSA_Encryptor<Pad>::Encrypt(const byte* plain, size_t sz, byte* cipher,
                                 RandomNumberGenerator& rng)
{
    PK_Lengths lengths(key_.GetModulus());

    if (sz > lengths.FixedMaxPlaintextLength())
        throw std::runtime_error("message too long for this public key");

    ByteBlock paddedBlock(lengths.PaddedBlockByteLength());
    padding_.Pad(plain, sz, paddedBlock.get_buffer(),
                 lengths.PaddedBlockBitLength(), rng);

    key_.ApplyFunction(Integer(paddedBlock.get_buffer(), paddedBlock.size())).
        Encode(cipher, lengths.FixedCiphertextLength());
}


template<class Pad>
size_t RSA_Decryptor<Pad>::Decrypt(const byte* cipher, size_t sz, byte* plain)
{
    PK_Lengths lengths(key_.GetModulus());

    if (sz != lengths.FixedCiphertextLength())
        throw std::runtime_error("bad cipher text size");

	ByteBlock paddedBlock(lengths.PaddedBlockByteLength());
	Integer x = key_.CalculateInverse(RandomNumberGenerator().Ref(), Integer(cipher,
                                      lengths.FixedCiphertextLength()).Ref());
	if (x.ByteCount() > paddedBlock.size())
		x = Integer::Zero();	// don't return false, prevents timing attack
	x.Encode(paddedBlock.get_buffer(), paddedBlock.size());
	return padding_.UnPad(paddedBlock.get_buffer(),
                          lengths.PaddedBlockBitLength(), plain);
}


typedef RSA_Encryptor<> RSAES_Encryptor;
typedef RSA_Decryptor<> RSAES_Decryptor;

// SSL type
typedef RSA_Encryptor<RSA_BlockType1> RSASSL_Encryptor;



template<class Pad>
void RSA_Decryptor<Pad>::SSL_Sign(const byte* message, size_t sz, byte* sig,
                                  RandomNumberGenerator& rng)
{
    RSA_PublicKey inverse;
    inverse.Initialize(key_.GetModulus(), key_.GetPrivateExponent());
    RSASSL_Encryptor enc(inverse);
    enc.Encrypt(message, sz, sig, rng);
}


void SSL_Decrypt(RSA_PublicKey& key, const byte* sig, size_t sz, byte* plain);


template<class Pad>
bool RSA_Encryptor<Pad>::SSL_Verify(const byte* message, size_t sz,
                                    const byte* sig)
{
    ByteBlock plain(PK_Lengths(key_.GetModulus()).FixedMaxPlaintextLength());
    SSL_Decrypt(key_, sig, sz, plain.get_buffer());

    if ( (memcmp(plain.get_buffer(), message, sz)) == 0)
        return true;
    return false;
}



} // namespace

#endif // TAO_CRYPT_RSA_HPP__
