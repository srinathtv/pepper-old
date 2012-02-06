#include <libv/libv.h>

Venezia::Venezia(int role, int crypto_in_use, int png_in_use) {
  crypto =
    new Crypto(get_crypto_type(role), crypto_in_use, png_in_use, false);
  init_venezia_state();
}

Venezia::Venezia(int role, int crypto_in_use, int png_in_use,
                 int public_key_mod_size) {
  crypto =
    new Crypto(get_crypto_type(role), crypto_in_use, png_in_use, false,
               public_key_mod_size);
  init_venezia_state();
}

Venezia::Venezia(int role, int crypto_in_use, int png_in_use,
                 int public_key_mod_size, int elgamal_priv_size) {
  crypto =
    new Crypto(get_crypto_type(role), crypto_in_use, png_in_use, false,
               public_key_mod_size, elgamal_priv_size);
  init_venezia_state();
}

int Venezia::get_crypto_type(int role) {
  if (role == ROLE_VERIFIER)
    return CRYPTO_TYPE_PRIVATE;
  else
    return CRYPTO_TYPE_PUBLIC;
}

void Venezia::init_venezia_state() {
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init(temp3);
  mpz_init(temp4);
}

void Venezia::create_commitment_query(uint32_t size, mpz_t * r_q,
                                      mpz_t * con_q, mpz_t prime) {
  for (uint32_t i = 0; i < size; i++) {
    crypto->get_random(con_q[i], prime);
    crypto->elgamal_enc(r_q[2 * i], r_q[2 * i + 1], con_q[i]);
  }
}

void Venezia::update_con_query(mpz_t con, mpz_t beta, mpz_t q, mpz_t prime) {
  mpz_mul(temp1, beta, q);
  mpz_add(con, con, temp1);
  // if (crypto->get_crypto_in_use() != CRYPTO_ELGAMAL)
  // mpz_mod(con, con, prime);
}

void Venezia::update_con_query_vec(uint32_t size, mpz_t * con, mpz_t beta,
                                   mpz_t * q, mpz_t prime) {
  for (uint32_t i = 0; i < size; i++)
    update_con_query(con[i], beta, q[i], prime);
}

void Venezia::create_lin_test_queries_streaming(uint32_t size,
                                                FILE * l1, FILE * l2,
                                                FILE * l3, mpz_t * con,
                                                int filled,
                                                mpz_t * con_coins,
                                                mpz_t prime) {
  crypto->get_random(con_coins[filled + 1], prime);
  crypto->get_random(con_coins[filled + 2], prime);
  crypto->get_random(con_coins[filled + 3], prime);

  size_t bytes;

  mpz_t l1_mpz, l2_mpz, l3_mpz;

  mpz_init_set_ui(l1_mpz, 0);
  mpz_init_set_ui(l2_mpz, 0);
  mpz_init_set_ui(l3_mpz, 0);

  for (uint32_t i = 0; i < size; i++) {
    crypto->get_random(l1_mpz, prime);
    crypto->get_random(l2_mpz, prime);

    // l3[i] = l1[i] + l2[i] % prime
    mpz_add(l3_mpz, l1_mpz, l2_mpz);
    // if (crypto->get_crypto_in_use() != CRYPTO_ELGAMAL)
    // mpz_mod(l3[i], l3[i], prime);

    // con[i] = con[i] + \con_coins_1 l1[i] + \con_coins_2 \l2[i]
    // \con_coins_3 l3[i]
    update_con_query(con[i], con_coins[filled + 1], l1_mpz, prime);
    update_con_query(con[i], con_coins[filled + 2], l2_mpz, prime);
    update_con_query(con[i], con_coins[filled + 3], l3_mpz, prime);

    mpz_out_raw(l1, l1_mpz);
    mpz_out_raw(l2, l2_mpz);
    mpz_out_raw(l3, l3_mpz);
  }
}

void Venezia::create_lin_test_queries(uint32_t size, mpz_t * l1,
                                      mpz_t * l2, mpz_t * l3, mpz_t * con,
                                      int filled, mpz_t * con_coins,
                                      mpz_t prime) {
  crypto->get_random(con_coins[filled + 1], prime);
  crypto->get_random(con_coins[filled + 2], prime);
  crypto->get_random(con_coins[filled + 3], prime);

  for (uint32_t i = 0; i < size; i++) {
    crypto->get_random(l1[i], prime);
    crypto->get_random(l2[i], prime);

    // l3[i] = l1[i] + l2[i] % prime
    mpz_add(l3[i], l1[i], l2[i]);
    // if (crypto->get_crypto_in_use() != CRYPTO_ELGAMAL)
    // mpz_mod(l3[i], l3[i], prime);

    // con[i] = con[i] + \con_coins_1 l1[i] + \con_coins_2 \l2[i]
    // \con_coins_3 l3[i]
    update_con_query(con[i], con_coins[filled + 1], l1[i], prime);
    update_con_query(con[i], con_coins[filled + 2], l2[i], prime);
    update_con_query(con[i], con_coins[filled + 3], l3[i], prime);
  }
}

void Venezia::create_corr_test_queries_vproduct(uint32_t m, mpz_t * f1_q1,
                                                mpz_t * f1_q2,
                                                mpz_t * f_q1, mpz_t * f_q2,
                                                mpz_t * con, int filled,
                                                mpz_t * con_coins,
                                                mpz_t prime) {
  crypto->get_random(con_coins[filled + 1], prime);
  crypto->get_random(con_coins[filled + 2], prime);

  for (uint32_t i = 0; i < m * m; i++) {
    crypto->get_random(f1_q1[i], prime);
    crypto->get_random(f1_q2[i], prime);
  }

  int index = 0;

  for (uint32_t i = 0; i < m; i++) {
    for (uint32_t j = 0; j < m; j++) {
      for (uint32_t k = 0; k < m; k++) {
        crypto->get_random(f_q2[index], prime);

        mpz_mul(f_q1[index], f1_q1[i * m + k], f1_q2[k * m + j]);
        mpz_add(f_q1[index], f_q1[index], f_q2[index]);
        // if (crypto->get_crypto_in_use() != CRYPTO_ELGAMAL)
        // mpz_mod(f_q1[index], f_q1[index], prime);

        update_con_query(con[index], con_coins[filled + 1], f_q1[index],
                         prime);
        update_con_query(con[index], con_coins[filled + 2], f_q2[index],
                         prime);
        index++;
      }
    }
  }
}

void Venezia::create_corr_test_queries(uint32_t size_1, mpz_t * c1_q,
                                       uint32_t size_2, mpz_t * c2_q,
                                       mpz_t * c3_q, mpz_t * r,
                                       mpz_t * con_q1, mpz_t * con_q2,
                                       mpz_t * con_q3, int filled1,
                                       mpz_t * con_coins1, int filled2,
                                       mpz_t * con_coins2, int filled3,
                                       mpz_t * con_coins3, mpz_t prime) {
  if (con_coins1 != NULL)
    crypto->get_random(con_coins1[filled1 + 1], prime);

  if (con_coins2 != NULL)
    crypto->get_random(con_coins2[filled2 + 1], prime);

  crypto->get_random(con_coins3[filled3 + 1], prime);
  crypto->get_random(con_coins3[filled3 + 2], prime);

  for (uint32_t i = 0; i < size_1; i++) {
    crypto->get_random(c1_q[i], prime);
    if (con_coins1 != NULL)
      update_con_query(con_q1[i], con_coins1[filled1 + 1], c1_q[i], prime);
  }

  for (uint32_t i = 0; i < size_2; i++) {
    crypto->get_random(c2_q[i], prime);
    if (con_coins2 != NULL)
      update_con_query(con_q2[i], con_coins2[filled2 + 1], c2_q[i], prime);
  }

  int index = 0;

  for (uint32_t i = 0; i < size_1; i++) {
    for (uint32_t j = 0; j < size_2; j++) {
      crypto->get_random(r[index], prime);
      mpz_mul(c3_q[index], c1_q[i], c2_q[j]);
      mpz_add(c3_q[index], c3_q[index], r[index]);
      // if (crypto->get_crypto_in_use() != CRYPTO_ELGAMAL)
      // mpz_mod(c3_q[index], c3_q[index], prime);

      update_con_query(con_q3[index], con_coins3[filled3 + 1], c3_q[index],
                       prime);
      update_con_query(con_q3[index], con_coins3[filled3 + 2], r[index],
                       prime);
      index++;
    }
  }
}

void Venezia::create_ckt_test_queries(uint32_t size, mpz_t * a,
                                      mpz_t * q_1, mpz_t * q_2,
                                      mpz_t * con_query, int filled,
                                      mpz_t * con_coins, mpz_t prime) {
  crypto->get_random(con_coins[filled + 1], prime);
  crypto->get_random(con_coins[filled + 2], prime);
  for (uint32_t i = 0; i < size; i++) {
    crypto->get_random(q_2[i], prime);
    mpz_add(q_1[i], q_2[i], a[i]);
    // if (crypto->get_crypto_in_use() != CRYPTO_ELGAMAL)
    // mpz_mod(q_1[i], q_1[i], prime);

    update_con_query(con_query[i], con_coins[filled + 1], q_1[i], prime);
    update_con_query(con_query[i], con_coins[filled + 2], q_2[i], prime);
  }
}

bool Venezia::lin_test(mpz_t a1, mpz_t a2, mpz_t a3, mpz_t prime) {
  mpz_add(temp1, a1, a2);
  mpz_mod(temp1, temp1, prime);
  mpz_mod(temp2, a3, prime);
  int temp = mpz_cmp(temp1, temp2);

  if (temp == 0)
    return true;
  else
    return false;
}

bool Venezia::corr_test(mpz_t a1, mpz_t a2, mpz_t a3, mpz_t a4,
                        mpz_t prime) {
  mpz_mul(temp1, a1, a2);
  mpz_mod(temp1, temp1, prime);
  mpz_sub(temp2, a3, a4);
  mpz_mod(temp2, temp2, prime);
  int temp = mpz_cmp(temp1, temp2);

  if (temp == 0)
    return true;
  else
    return false;
}

bool Venezia::ckt_test(uint32_t size, mpz_t * arr, mpz_t c, mpz_t prime) {
  mpz_init_set_ui(temp1, 0);
  for (uint32_t i = 0; i < size / 2; i++) {
    mpz_sub(temp1, arr[2 * i], arr[2 * i + 1]);
    mpz_add(c, c, temp1);
  }
  mpz_mod(c, c, prime);
  if (mpz_cmp_ui(c, 0) == 0)
    return true;
  else
    return false;
}

bool Venezia::consistency_test(uint32_t size, mpz_t con_answer,
                               mpz_t com_answer, mpz_t * answers,
                               mpz_t * con_coins, mpz_t prime) {
  mpz_set_ui(temp1, 0);
  // REVISIT: need to get rid of these in the next version
  crypto->elgamal_get_generator(&temp3);
  crypto->elgamal_get_public_modulus(&temp4);

  for (uint32_t i = 0; i < size; i++) {
    mpz_mul(temp2, con_coins[i], answers[i]);
    mpz_add(temp1, temp1, temp2);
  }

  mpz_powm(temp1, temp3, temp1, temp4);
  mpz_mul(temp1, temp1, com_answer);
  mpz_mod(temp1, temp1, temp4);

  mpz_powm(temp2, temp3, con_answer, temp4);

  if (mpz_cmp(temp1, temp2) == 0)
    return true;
  else
    return false;
}

void Venezia::dot_product(uint32_t size, mpz_t * q, mpz_t * d,
                          mpz_t output, mpz_t prime) {
  mpz_set_ui(output, 0);
  mpz_t temp;

  mpz_init(temp);

  for (uint32_t i = 0; i < size; i++) {
    mpz_mul(temp, d[i], q[i]);
    mpz_add(output, output, temp);
  }
}

// wrapper on top of crypto
void Venezia::get_random_vec(uint32_t size, mpz_t * vec, mpz_t n) {
  return crypto->get_random_vec(size, vec, n);
}

void Venezia::get_random(mpz_t x, mpz_t p) {
  crypto->get_random(x, p);
}

void Venezia::get_random_vec(uint32_t size, mpz_t * vec, int nbits) {
  return crypto->get_random_vec(size, vec, nbits);
}

void Venezia::get_random_vec(uint32_t size, mpq_t *vec, int nbits) {
  for (unsigned i = 0; i < size; i++)
  {
    // Calls random twice, but hopefully, with half the bit size,
    // it's no worse than calling once with full bit size.
    crypto->get_randomb(mpq_numref(vec[i]), (nbits / 2));

    do { // No 0 in denominator
      crypto->get_randomb(mpq_denref(vec[i]), (nbits / 2));
    }
    while (mpz_cmp_ui(mpq_denref(vec[i]), 0) == 0);

    mpq_canonicalize(vec[i]);
  }
}

void Venezia::paillier_dec(mpz_t plain, mpz_t cipher) {
  return crypto->paillier_dec(plain, cipher);
}

void Venezia::elgamal_dec(mpz_t plain, mpz_t c1, mpz_t c2) {
  return crypto->elgamal_dec(plain, c1, c2);
}

void Venezia::dot_product_enc(uint32_t size, mpz_t * q, mpz_t * d,
                              mpz_t output) {
  return crypto->dot_product_enc(size, q, d, output);
}

void Venezia::dot_product_enc(uint32_t size, mpz_t * q, mpz_t * d,
                              mpz_t output, mpz_t output2) {
  return crypto->dot_product_enc(size, q, d, output, output2);
}
