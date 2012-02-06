#ifndef CODE_PEPPER_APPS_POLYEVAL_D3_V_H_
#define CODE_PEPPER_APPS_POLYEVAL_D3_V_H_

#include <libv/verifier.h>

#define NAME_PROVER "polyeval_d3_p"
#define NUM_LIN_PCP_QUERIES 8
#define L1 0
#define L2 1
#define L3 2
#define Q1 3
#define Q2 4
#define Q3 5
#define C1 6
#define C2 7

bool MICROBENCHMARKS = false;

class PolyEvalD3Verifier : public Verifier {
  private:
    int num_coefficients; 
    mpz_t *f1_q1, *f1_q2, *f1_q3, *f1_commitment, *f1_consistency;
    mpz_t *f2_q1, *f2_q2, *f2_q3, *f2_commitment, *f2_consistency;
    mpz_t *f3_q1, *f3_q2, *f3_q3, *f3_commitment, *f3_consistency;
    mpz_t *coefficients, *input, *alpha;
    mpz_t neg, neg_i;
    mpz_t temp, output;
    mpz_t *f1_con_coins, *f2_con_coins, *f3_con_coins;
    mpz_t *f1_answers, *f2_answers, *f3_answers;
    mpz_t *ckt_answers, *temp_arr, *temp_arr2, *temp_arr3;
    mpz_t a1, a2, a3, f1_s, f2_s, f3_s;

  public:
    PolyEvalD3Verifier(int batch, int reps, int ip_size, int optimize_answers, char *prover_url);
    void init_state();
    void create_input();
    void create_plain_queries();
    void run_correction_and_circuit_tests(uint32_t beta);
    void recv_outputs();
};
#endif  // CODE_PEPPER_APPS_POLYEVAL_D3_V_H_
