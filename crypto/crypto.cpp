#include <crypto/crypto.h> 

Crypto::Crypto(int c_type, int c_in_use, int p_in_use) {
  type = c_type;
  crypto_in_use = c_in_use;
  png_in_use = p_in_use;
  public_key_mod_bits = DEFAULT_PUBLIC_KEY_MOD_BITS;
  elgamal_priv_rand_bits = DEFAULT_ELGAMAL_PRIV_RAND_BITS;
  init_crypto_state(false);
}

Crypto::Crypto(int c_type, int c_in_use, int p_in_use, bool gen_keys) {
  type = c_type;
  crypto_in_use = c_in_use;
  png_in_use = p_in_use;
  public_key_mod_bits = DEFAULT_PUBLIC_KEY_MOD_BITS;
  elgamal_priv_rand_bits = DEFAULT_ELGAMAL_PRIV_RAND_BITS;
  init_crypto_state(gen_keys);
}

Crypto::Crypto(int c_type, int c_in_use, int p_in_use, bool gen_keys,
               int public_key_mod_size) {
  type = c_type;
  crypto_in_use = c_in_use;
  png_in_use = p_in_use;  
  public_key_mod_bits = public_key_mod_size;
  elgamal_priv_rand_bits = DEFAULT_ELGAMAL_PRIV_RAND_BITS;
  init_crypto_state(gen_keys);
}

Crypto::Crypto(int c_type, int c_in_use, int p_in_use, bool gen_keys,
               int public_key_mod_size, int elgamal_priv_size) {
  type = c_type;
  crypto_in_use = c_in_use;
  png_in_use = p_in_use;  
  public_key_mod_bits = public_key_mod_size;
  elgamal_priv_rand_bits = elgamal_priv_size;
  init_crypto_state(gen_keys);
}

int Crypto::get_crypto_in_use() {
  return crypto_in_use;
}

void Crypto::init_crypto_state(bool gen_keys) {
  gmp_randinit_default(state);

  // temp variables used in all crypto functions 
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init(p);
  mpz_init(q);
  mpz_init(lambda);
  mpz_init(g);
  mpz_init(mu);
  mpz_init(n2);
  mpz_init(n);
  mpz_init(gr);
  mpz_init(r);

  if (png_in_use == PNG_SFS)
    init_sfslite_png();
  else if (png_in_use == PNG_CHACHA)
    init_chacha_png();

  // make sure to initialize prng before the next set of statements
  if (gen_keys == false)
    load_crypto_state(type);
  else
    generate_crypto_keys();
}

void Crypto::load_crypto_state(int type) {
  char file_name[BUFLEN];
  int expansion_factor;

  mpz_t p, q, g, r, n;
  mpz_init(p);
  mpz_init(q);
  mpz_init(g);
  mpz_init(r);
  mpz_init(n);

  if (crypto_in_use == CRYPTO_PAILLIER)
    expansion_factor = 1;
  else if (crypto_in_use == CRYPTO_ELGAMAL)
    expansion_factor = 2;

  // initialize the keys
  if (type == CRYPTO_TYPE_PRIVATE)
  {
    if (crypto_in_use == CRYPTO_PAILLIER)
    {
      snprintf(file_name, BUFLEN-1, "privkey_p_%d.txt", public_key_mod_bits);
      load_txt_scalar(p, file_name, (char *)"static_state/paillier_keys");

      snprintf(file_name, BUFLEN-1, "privkey_q_%d.txt", public_key_mod_bits);
      load_txt_scalar(q, file_name, (char *)"static_state/paillier_keys");

      set_paillier_priv_key(p, q);
    }
    else if (crypto_in_use == CRYPTO_ELGAMAL)
    {
      snprintf(file_name, BUFLEN-1, "pubkey_prime_%d.txt", public_key_mod_bits);
      load_txt_scalar(p, file_name, (char *)"static_state");

      snprintf(file_name, BUFLEN-1, "pubkey_gen_%d.txt", public_key_mod_bits);
      load_txt_scalar(g, file_name, (char *)"static_state");

      snprintf(file_name, BUFLEN-1, "privkey_r_%d.txt", public_key_mod_bits);
      load_txt_scalar(r, file_name, (char *)"static_state");

      set_elgamal_priv_key(p, g, r);
    }
  }
  else
  {
    if (crypto_in_use == CRYPTO_PAILLIER)
    {
      snprintf(file_name, BUFLEN-1, "pubkey_n_%d.txt", public_key_mod_bits);
      load_txt_scalar(n, file_name, (char *)"static_state/paillier_keys");
      set_paillier_pub_key(n);
    }
    else if (crypto_in_use == CRYPTO_ELGAMAL)
    {
      snprintf(file_name, BUFLEN-1, "pubkey_prime_%d.txt", public_key_mod_bits);
      load_txt_scalar(p, file_name, (char *)"static_state");

      snprintf(file_name, BUFLEN-1, "pubkey_gen_%d.txt", public_key_mod_bits);
      load_txt_scalar(g, file_name, (char *)"static_state");

      set_elgamal_pub_key(p, g);
    }
  }
}

void Crypto::generate_crypto_keys() {
  if (crypto_in_use == CRYPTO_ELGAMAL)
    generate_elgamal_crypto_keys();
  else if (crypto_in_use == CRYPTO_PAILLIER)
    generate_paillier_crypto_keys();
}

void Crypto::generate_elgamal_crypto_keys() {
  cout<<"Key generation"<<endl;
  cout<<"cryptosystem elgamal"<<endl;
  cout<<"public_key_mod_size "<<public_key_mod_bits<<endl;
  cout<<"private_rand_size "<<elgamal_priv_rand_bits<<endl;
  cout<<"randomness "<< png_in_use<<endl;

  // select a prime
  do
  {
    find_prime(q, public_key_mod_bits-1);

    mpz_mul_ui(p, q, 2);
    mpz_add_ui(p, p, 1);
  } while ((mpz_sizeinbase(p, 2) != (uint32_t)public_key_mod_bits) && (mpz_probab_prime_p(p, 15) != 0)); 

  // select a random g in Z_{p-1}
  mpz_sub_ui(temp1, p, 1);
  get_random(g, temp1);
  mpz_mul(g, g, g);
  mpz_mod(g, g, p);

  get_randomb(r, elgamal_priv_rand_bits); 
  elgamal_precompute();
}


void Crypto::elgamal_precompute() {
  mpz_powm(gr, g, r, p);
}

void Crypto::elgamal_get_generator(mpz_t *g_arg) {
  mpz_set(*g_arg, g);
}

void Crypto::elgamal_get_public_modulus(mpz_t *p_arg) {
  mpz_set(*p_arg, p);
}

int Crypto::get_public_modulus_size() {
  return public_key_mod_bits;
}

int Crypto::get_elgamal_priv_key_size() {
  return elgamal_priv_rand_bits;
}


void Crypto::elgamal_enc(mpz_t c1, mpz_t c2, mpz_t plain) {
  // select a random number of size PRIV_KEY_BITS
  get_randomb(temp1, elgamal_priv_rand_bits);
  mpz_powm(c1, g, temp1, p);

  // encode plain text as plain' = g^{plain}
  mpz_powm(temp2, g, plain, p);

  mpz_powm(c2, gr, temp1, p);
  mpz_mul(c2, c2, temp2);
  mpz_mod(c2, c2, p);
}

void Crypto::elgamal_dec(mpz_t plain, mpz_t c1, mpz_t c2) {
  mpz_powm(plain, c1, r, p);
  mpz_invert(plain, plain, p);
  mpz_mul(plain, plain, c2);
  mpz_mod(plain, plain, p);
}

void Crypto::elgamal_hadd(mpz_t res1, mpz_t res2, mpz_t c1_1, mpz_t c1_2, mpz_t c2_1, mpz_t c2_2) {
  mpz_mul(res1, c1_1, c2_1);
  mpz_mod(res1, res1, p);

  mpz_mul(res2, c1_2, c2_2);
  mpz_mod(res2, res2, p);
}

void Crypto::elgamal_smul(mpz_t res1, mpz_t res2, mpz_t c1, mpz_t c2, mpz_t coefficient) {
  mpz_powm(res1, c1, coefficient, p);
  mpz_powm(res2, c2, coefficient, p);
}

void Crypto::set_elgamal_pub_key(mpz_t p_arg, mpz_t g_arg) {
  mpz_set(p, p_arg);
  mpz_set(g, g_arg);
}

void Crypto::set_elgamal_priv_key(mpz_t p_arg, mpz_t g_arg, mpz_t r_arg) {
  mpz_set(p, p_arg);
  mpz_set(g, g_arg);
  mpz_set(r, r_arg);
  elgamal_precompute();
}

void Crypto::set_paillier_pub_key(mpz_t n_arg) {
  mpz_set(n, n_arg);

  //g = n + 1
  mpz_add_ui(g, n, 1);

  // n2 = n^2 = n*n
  mpz_mul(n2, n, n);
}

void Crypto::set_paillier_priv_key(mpz_t p_arg, mpz_t q_arg) {
  mpz_set(p, p_arg);
  mpz_set(q, q_arg);

  // temp variables used in all crypto functions 
  mpz_init(temp1);
  mpz_init(temp2);

  // lambda = (p-1)*(q-1)
  mpz_sub_ui(temp1, p, 1);
  mpz_sub_ui(temp2, q, 1);
  mpz_mul(lambda, temp1, temp2);

  // n = p*q
  mpz_mul(n, p, q);

  //g = n + 1
  mpz_add_ui(g, n, 1);

  // mu = 1/lambda mod n
  mpz_invert(mu, lambda, n);

  // n2 = n^2 = n*n
  mpz_mul(n2, n, n);

  // precompute g^n mod n^2
  mpz_powm(gn, g, n, n2);
}


void Crypto::generate_paillier_crypto_keys() {
  cout<<"cryptosystem paillier"<<endl;
  cout<<"public_key_mod_size "<<public_key_mod_bits<<endl;
  mpz_init(p);
  mpz_init(q);
  mpz_init(n);
  mpz_init(lambda);
  mpz_init(g);
  mpz_init(mu);
  mpz_init(n2);
  mpz_init(gn);

  // temp variables used in all crypto functions 
  mpz_init(temp1);
  mpz_init(temp2);

  // get two primes each of size mod/2 bits
  find_prime(p, public_key_mod_bits/2);
  find_prime(q, public_key_mod_bits/2);

  // lambda = (p-1)*(q-1)
  mpz_sub_ui(temp1, p, 1);
  mpz_sub_ui(temp2, q, 1);
  mpz_mul(lambda, temp1, temp2);

  // n = p*q
  mpz_mul(n, p, q);

  //g = n + 1
  mpz_add_ui(g, n, 1);

  // mu = 1/lambda mod n
  mpz_invert(mu, lambda, n);

  // n2 = n^2 = n*n
  mpz_mul(n2, n, n);

  // precompute g^n mod n^2
  mpz_powm(gn, g, n, n2);
}


void Crypto::paillier_enc(mpz_t cipher, mpz_t plain) {
  // cipher = g^{nr + plain} mod n^2
  get_random(temp1, n);

  mpz_powm(temp1, gn, temp1, n2);
  mpz_powm(temp2, g, plain, n2);
  mpz_mul(cipher, temp2, temp1);
  mpz_mod(cipher, cipher, n2);
}

void Crypto::paillier_dec(mpz_t plain, mpz_t cipher) {
  mpz_powm(plain, cipher, lambda, n2);
  mpz_sub_ui(plain, plain, 1);
  mpz_div(plain, plain, n);
  mpz_mul(plain, plain, mu);
  mpz_mod(plain, plain, n);
}

void Crypto::paillier_hadd(mpz_t result, mpz_t op1, mpz_t op2) {
  mpz_mul(result, op1, op2);
  mpz_mod(result, result, n2);
}

void Crypto::paillier_smul(mpz_t result, mpz_t cipher, mpz_t plain) {
  mpz_powm(result, cipher, plain, n2);
}

void Crypto::get_random_vec(uint32_t size, mpz_t *vec, mpz_t n) {
  for (uint32_t i = 0; i < size; i++)
    get_random(vec[i], n);
}

void Crypto::get_random_vec(uint32_t size, mpz_t *vec, int nbits) {
  for (uint32_t i = 0; i < size; i++)
    get_randomb(vec[i], nbits);
}

void Crypto::get_random(mpz_t m, mpz_t n) {
  if (png_in_use == PNG_CHACHA)
    chacha_urandom(m, n);
  else if (png_in_use == PNG_MT)
    mpz_urandomm(m, state, n);
  else if (png_in_use == PNG_SFS)
    sfslite_urandom(m, n);
}

void Crypto::get_randomb(mpz_t m, int nbits) {
  if (png_in_use == PNG_CHACHA)
    chacha_urandomb(m, nbits);  
  else if (png_in_use == PNG_MT)
    mpz_urandomb(m, state, nbits);
  else if (png_in_use == PNG_SFS)
    sfslite_urandomb(m, nbits);
}

void Crypto::find_prime(mpz_t prime, unsigned long int n) {
  get_randomb(prime, n);

  while (mpz_probab_prime_p(prime, 15) == 0)
    get_randomb(prime, n);
}

void Crypto::init_sfslite_png() {
  random_start();
}

// generates random number using sfslite random
void Crypto::sfslite_urandom(mpz_t m, mpz_t n) {  
  // figure out numbers of bits in n
  int nbits = int(mpz_sizeinbase(n, 2));

  // loop until m < n
  do
  {
    sfslite_urandomb(m, nbits);
  } while (mpz_cmp(m, n) >= 0);
}

// generates random bits using sfslite random
void Crypto::sfslite_urandomb(mpz_t m, int nbits) {
  // figure out number of bytes
  int nbytes = ceil(double(nbits)/8);
  //cout << "bytes: " << nbytes << endl;

  // figure out number of bits to cut off
  int diff = nbytes*8 - nbits;

  // create buffer to hold raw
  unsigned char buff[nbytes];

  // generate random as raw into buffer
  rnd.getbytes(buff, sizeof(buff));

  // convert raw to mpz_t
  mpz_import(m, sizeof buff, 1, sizeof(buff[0]), 0, 0, buff);

  // remove extra bits if needed
  if (diff != 0)
    mpz_fdiv_q_2exp (m, m, diff);
}

void Crypto::init_chacha_png() {
  chacha = (ECRYPT_ctx*)aligned_malloc(sizeof(ECRYPT_ctx));
  random_state = new u8[RANDOM_STATE_SIZE];

  u8 key[256];
  u8 iv[64];

  ifstream rand;

  rand.open("/dev/urandom", ifstream::in);
  rand.read((char*)&key, (size_t)(256/8));
  rand.read((char*)&iv, (size_t)(64/8));
  rand.close();

  ECRYPT_keysetup(chacha, key, 256, 64);
  ECRYPT_ivsetup(chacha, iv);

  chacha_new_random();

  return;
}

// generates random number using chacha random
void Crypto::chacha_urandom(mpz_t m, mpz_t n) {
  // figure out numbers of bits in n
  int nbits = int(mpz_sizeinbase(n, 2));

  // loop until m < n
  do
  {
    chacha_urandomb(m, nbits);
  } while (mpz_cmp(m, n) >= 0);
}

// generates random bits using one big call to chacha and keeping state
void Crypto::chacha_urandomb(mpz_t m, int nbits) {

  // determine number of bytes
  int nbytes = ceil(double(nbits)/8);
  int diff = (nbytes <<3) - nbits;

  // check that we have enough randomness
  if ((RANDOM_STATE_SIZE-random_index) < nbytes)
    chacha_new_random();

   // convert raw to mpz_t
  fast_mpz_import(m, &random_state[random_index], nbytes);
 
   // update index
  random_index += nbytes;

  // remove extra bits if needed
  if (diff != 0)  
    mpz_fdiv_q_2exp(m, m, diff);  
}

// generate new random state
void Crypto::chacha_new_random() {
  //cout << "called" << endl;
  ECRYPT_keystream_bytes(chacha, random_state, RANDOM_STATE_SIZE);
  random_index = 0;
}

void Crypto::dot_product_enc(uint32_t size, mpz_t *q, mpz_t *d, mpz_t output) {
  mpz_set_ui(output, 1);
  if (crypto_in_use == CRYPTO_PAILLIER)
  {
    for (uint32_t i=0; i<size; i++)
    {
      paillier_smul(temp1, q[i], d[i]);
      paillier_hadd(output, output, temp1);
    }
  }
}

void Crypto::dot_product_enc(uint32_t size, mpz_t *q, mpz_t *d, mpz_t output, mpz_t output2) {
  mpz_set_ui(output, 1);
  mpz_set_ui(output2, 1);
  #pragma omp parallel shared(output,output2) num_threads(4)
  {
    cout <<"dot_product_enc_num_threads "<< omp_get_num_threads()<<endl;
    mpz_t temp1, temp2;
    mpz_t priv_output;
    mpz_t priv_output2;
    mpz_init_set_ui(priv_output, 1);
    mpz_init_set_ui(priv_output2, 1);
    mpz_init(temp1);
    mpz_init(temp2);

    if (crypto_in_use == CRYPTO_ELGAMAL)
    { 
      #pragma omp for
      for (uint32_t i=0; i<size; i++)
      {
        elgamal_smul(temp1, temp2, q[2*i], q[2*i+1], d[i]);
        elgamal_hadd(priv_output, priv_output2, priv_output, priv_output2, temp1, temp2);
      }
      #pragma omp critical
      {
        elgamal_hadd(output, output2, output, output2, priv_output, priv_output2);
      }
    }
  }
}
