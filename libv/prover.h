#ifndef CODE_PEPPER_LIBV_PROVER_H_
#define CODE_PEPPER_LIBV_PROVER_H_

#include <libv/libv.h>
#include <common/utility.h>
#include <common/measurement.h>
#include <fcgi_stdio.h>
#define FOLDER_WWW_DOWNLOAD "/mnt/computation_state"

class Prover {
  protected:
    Venezia * v;
    Measurement m_comp, m_proof_work;
    uint32_t num_bits_in_input;
    uint32_t num_bits_in_prime;
    char scratch_str[BUFLEN];
    char scratch_str2[BUFLEN];
    int crypto_in_use;
    int png_in_use;
    int expansion_factor;
    mpz_t prime;
    int phase;
    int batch_size;
    int num_repetitions;
    int m;
    int optimize_answers;
    mpz_t answer;

    int num_lin_queries, num_corr_queries, num_ckt_queries;
    vector < mpz_t * >F_ptrs;
    vector < mpz_t * >f_q_ptrs;
    vector < int >sizes;

  public:
    virtual void prover_computation_commitment() = 0;
    virtual void find_cur_qlengths() = 0;
    void init_state();
    void prover_answer_query(uint32_t size, mpz_t * q, char *q_name, mpz_t
                             * assignment, mpz_t answer, mpz_t prime,
                             char *a_name, FILE * fp);
    Prover(int ph, int b_size, int num_r, int i_size);
    void handle_terminal_request();
    void handle_http_requests();
    void prover_answer_queries();
};

#endif  // CODE_PEPPER_LIBV_PROVER_H_
