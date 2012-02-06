#ifndef CODE_PEPPER_CRYPTO_CRYPTO_H_  
#define CODE_PEPPER_CRYPTO_CRYPTO_H_  
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <omp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <math.h>
#include <common/utility.h>
#include <fstream>
extern "C" {
#include "ecrypt-sync.h"
}

#include "crypt.h"

#define CRYPTO_ELGAMAL 0
#define CRYPTO_PAILLIER 1
#define PNG_MT 0
#define PNG_SFS 2
#define PNG_CHACHA 3
#define DEFAULT_PUBLIC_KEY_MOD_BITS 1280 
#define DEFAULT_ELGAMAL_PRIV_RAND_BITS 160
#define CRYPTO_TYPE_PUBLIC 0
#define CRYPTO_TYPE_PRIVATE 1
#define BUFLEN 1024

// must be factor of mp_bits_per_limb for split()
#define RANDOM_STATE_SIZE (3000*mp_bits_per_limb/8)

using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::ifstream;

class Crypto {
  private:
    // global state
    gmp_randstate_t state;
    
    int crypto_in_use;
    int png_in_use;
    int type;

    int public_key_mod_bits;
    int elgamal_priv_rand_bits;
 
    ECRYPT_ctx *chacha; 
    mpz_t n, p, q, lambda, g, mu, n2, temp1, temp2, gn, gr, r;

    u8 * random_state;
    int random_index;

  public:
 
    // GENERAL:
    Crypto(int, int, int); 
    Crypto(int, int, int, bool);
    Crypto(int, int, int, bool, int);
    Crypto(int, int, int, bool, int, int);
    
    
    // initialize/generate crypto state
    void init_crypto_state(bool);
    void load_crypto_state(int);
    void generate_crypto_keys();
    int get_crypto_in_use();
    int get_public_modulus_size();
    int get_elgamal_priv_key_size();

    // paillier
    // init
    void generate_paillier_crypto_keys();
    void set_paillier_pub_key(mpz_t n);
    void set_paillier_priv_key(mpz_t p, mpz_t q);
   
    // operations
    void paillier_enc(mpz_t cipher, mpz_t plain);
    void paillier_dec(mpz_t plain, mpz_t cipher);
    void paillier_hadd(mpz_t result, mpz_t op1, mpz_t op2);
    void paillier_smul(mpz_t result, mpz_t cipher, mpz_t plain);
    void dot_product_enc(uint32_t size, mpz_t *q, mpz_t *d, mpz_t output);
   
    // ElGamal
    // init
    void generate_elgamal_crypto_keys();
    void set_elgamal_pub_key(mpz_t p_arg, mpz_t g_arg);
    void set_elgamal_priv_key(mpz_t p_arg, mpz_t g_arg, mpz_t r_arg);
    void elgamal_precompute();
    void elgamal_get_generator(mpz_t *g_arg);
    void elgamal_get_public_modulus(mpz_t *p_arg);

    // operations
    void elgamal_enc(mpz_t c1, mpz_t c2, mpz_t plain);
    void elgamal_dec(mpz_t plain, mpz_t c1, mpz_t c2); void
    elgamal_hadd(mpz_t res1, mpz_t res2, mpz_t c1_1, mpz_t c1_2, mpz_t
      c2_1, mpz_t c2_2); 
    void elgamal_smul(mpz_t res1, mpz_t res2, mpz_t c1, mpz_t c2, mpz_t
      coefficient);
    void dot_product_enc(uint32_t size, mpz_t *q, mpz_t *d, mpz_t output, mpz_t output2);

    // png routines
    void get_random(mpz_t m, mpz_t n);
    void get_randomb(mpz_t m, int nbits);
    void get_random_vec(uint32_t size, mpz_t *vec, mpz_t n);
    void get_random_vec(uint32_t size, mpz_t *vec, int nbits);
    void find_prime(mpz_t prime, unsigned long int n);
    void init_sfslite_png();
    void sfslite_urandom(mpz_t m, mpz_t n);
    void sfslite_urandomb(mpz_t m, int nbits);
    void init_chacha_png();
    void chacha_urandom(mpz_t m, mpz_t n);
    void chacha_urandomb(mpz_t m, int nbits);
    void chacha_new_random();
};
#endif  // CODE_PEPPER_CRYPTO_CRYPTO_H_
