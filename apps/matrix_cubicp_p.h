#ifndef CODE_PEPPER_APPS_MATRIX_CUBICP_P_H_ 
#define CODE_PEPPER_APPS_MATRIX_CUBICP_P_H_

#include <libv/prover.h>

bool MICROBENCHMARKS = false;

class MatrixCubicProver : public Prover {
  
  private:
    mpz_t *A, *B, *C, *F1, *output, *f1_commitment, *f1_q;
    int hadamard_code_size;

  public:
    MatrixCubicProver(int, int, int, int);
    void init_state();
    void find_cur_qlengths();
    void prover_computation_commitment();
    void computation_matrixmult ();
};
#endif  // CODE_PEPPER_APPS_MATRIX_CUBICP_P_H_
