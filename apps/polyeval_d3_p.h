#ifndef CODE_PEPPER_APPS_POLYEVAL_D3_P_H_
#define CODE_PEPPER_APPS_POLYEVAL_D3_P_H_
#include <libv/prover.h>

bool MICROBENCHMARKS = false;
class PolyEvalD3Prover : public Prover {
  private:
    mpz_t *variables, *coefficients, *output, *F1, *F2, *F3;
    mpz_t *f1_commitment, *f2_commitment, *f3_commitment;
    mpz_t *f1_consistency, *f2_consistency, *f3_consistency;
    mpz_t *f1_q, *f2_q, *f3_q;
    mpz_t temp, temp2;
    int num_coefficients;

  public:
    PolyEvalD3Prover(int, int, int, int);
    void init_state();
    void find_cur_qlengths();
    void prover_computation_commitment();
    void computation_polyeval(mpz_t);
};

#endif  // CODE_PEPPER_APPS_POLYEVAL_D3_P_H_
