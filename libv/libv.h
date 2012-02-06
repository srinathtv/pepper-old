#ifndef CODE_PEPPER_LIBV_LIBV_H_
#define CODE_PEPPER_LIBV_LIBV_H_

#include <crypto/crypto.h>
#include <math.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <stdint.h>
#include <vector>
#include <algorithm>

#define ROLE_VERIFIER 0
#define ROLE_PROVER 1

#define PHASE_PROVER_COMMITMENT 1
#define PHASE_PROVER_PCP 2

class Venezia {
  private:
    Crypto * crypto;
    mpz_t temp1, temp2, temp3, temp4;

  public:
    Venezia(int, int, int);
    Venezia(int, int, int, int);
    Venezia(int, int, int, int, int);

    void init_venezia_state();
    void dot_product(uint32_t size, mpz_t * q, mpz_t * d, mpz_t output,
                     mpz_t prime);
    void update_con_query(mpz_t con, mpz_t beta, mpz_t q, mpz_t prime);
    void update_con_query_vec(uint32_t size, mpz_t * con, mpz_t beta,
                              mpz_t * q, mpz_t prime);
    int get_crypto_type(int role);

    // VERIFIER:
    // creates a random commitment query of size "size" and stores the
    // result in the array r; the computation also submits another
    // array
    // where the consistency query is maintained. if the computation's
    // prover holds multiple functions; a commitment query is created
    // per function
    void create_commitment_query(uint32_t size, mpz_t *r_q, mpz_t *con_q,
                                 mpz_t prime);

    void create_lin_test_queries(uint32_t size, mpz_t * l1, mpz_t * l2,
                                 mpz_t * l3, mpz_t * con, int filled,
                                 mpz_t * con_coins, mpz_t prime);
    void create_lin_test_queries_streaming(uint32_t size,
                                           FILE * l1, FILE * l2, FILE * l3,
                                           mpz_t * con, int filled,
                                           mpz_t * con_coins, mpz_t prime);

    // creates quad test queries c1_q (of size s_1), c2_q (of size s_2)
    // and
    // then does c3_q = \op{c1_q}{c2_q} + r and returns r. since there
    // could
    // be queries of at most 3 sizes, three pointers to consistency
    // queries
    // are passed.
    void create_corr_test_queries(uint32_t size_1, mpz_t * c1_q,
                                  uint32_t size_2, mpz_t * c2_q,
                                  mpz_t * c3_q, mpz_t * r, mpz_t * con_q1,
                                  mpz_t * con_q2, mpz_t * con_q3,
                                  int filled1, mpz_t * con_coins1, int
                                  filled2, mpz_t * con_coins2, int filled3,
                                  mpz_t * con_coins3, mpz_t prime);

    void create_corr_test_queries_vproduct(uint32_t m, mpz_t * f1_q1,
                                           mpz_t * f1_q2, mpz_t * f_q1,
                                           mpz_t * f_q2, mpz_t * con,
                                           int filled, mpz_t * con_coins,
                                           mpz_t prime);

    // the computation specifies the matrix/vector obtained via
    // arithmetization and this function returns two vectors q_1 is
    // basically (a + q_2).
    void create_ckt_test_queries(uint32_t size, mpz_t * a, mpz_t * q_1,
                                 mpz_t * q_2, mpz_t * con_query, int filled,
                                 mpz_t * con_coins, mpz_t prime);

    // PROVER:
    // By now, the verifier has commitment query (one per prover's
    // function),
    // PCP queries, and consistency query (one per prover's function)

    // Now the verifier can create its input and invoke the prover's
    // functions; this is computation-specific and will not be
    // implemented
    // by the library. the function inside might also compute
    // additional
    // vectors to answer verifier's queries.
    // do_computation(input, output, a_1, a_2, ... );

    // computes dot product of two vectors of size "size"
    // dotproduct(size, q1, q2)
    // dotproduct(size, encrypted_q1, q2)

    // VERIFIER:
    bool consistency_test(uint32_t size, mpz_t con_answer, mpz_t
                          com_answer, mpz_t * answers, mpz_t * con_coins,
                          mpz_t prime);
    bool lin_test(mpz_t a1, mpz_t a2, mpz_t a3, mpz_t prime);
    bool corr_test(mpz_t a1, mpz_t a2, mpz_t a3, mpz_t a4, mpz_t prime);

    // the following just does \sum_{i=1}{size/2}(arr[2i] - arr[2i+1])
    // + c
    // =? 0
    bool ckt_test(uint32_t size, mpz_t * arr, mpz_t c, mpz_t prime);

    void get_random(mpz_t x, mpz_t p);
    void get_random_vec(uint32_t size, mpz_t * vec, mpz_t n);
    void get_random_vec(uint32_t size, mpz_t * vec, int nbits);
    void get_random_vec(uint32_t size, mpq_t * vec, int nbits);
    void paillier_dec(mpz_t plain, mpz_t cipher);
    void elgamal_dec(mpz_t plain, mpz_t c1, mpz_t c2);
    void dot_product_enc(uint32_t size, mpz_t * q, mpz_t * d, mpz_t output);
    void dot_product_enc(uint32_t size, mpz_t * q, mpz_t * d, mpz_t output,
                         mpz_t output2);
};
#endif  // CODE_PEPPER_LIBV_LIBV_H_
