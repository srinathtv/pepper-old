#ifndef CODE_PEPPER_APPS_MATRIX_CUBICP_V_H_
#define CODE_PEPPER_APPS_MATRIX_CUBICP_V_H_

#include <libv/verifier.h>
#include <papi.h>

#define NAME_PROVER "matrix_cubicp_p"
#define NUM_LIN_PCP_QUERIES 7
#define L1 0
#define L2 1
#define L3 2
#define Q1 3
#define Q2 4
#define C1 5
#define C2 6

bool MICROBENCHMARKS = 0;

class MatrixCubicVerifier : public Verifier {
  private:
    mpz_t *f1_commitment, *f1_consistency;
    mpz_t *A, *B, *C;
    mpz_t *f1_q1, *f1_q2, *f1_q3;
    mpz_t *f2_q1, *f2_q2;
    mpz_t *f1_con_coins;
    mpz_t *gamma;
    mpz_t temp, temp2, f1_s, a1, a2, a3;
    mpz_t *f1_answers, *f2_answers, *ckt_answers;
    mpz_t *temp_arr;

    int hadamard_code_size;
  
  public:
    MatrixCubicVerifier(int batch, int reps, int ip_size, int optimize_answers, char *prover_url);
    void init_state();
    void create_input();
    void create_plain_queries();
    void run_correction_and_circuit_tests(uint32_t beta);
    void recv_outputs(); 
};
#endif  // CODE_PEPPER_APPS_MATRIX_CUBICP_V_H_
