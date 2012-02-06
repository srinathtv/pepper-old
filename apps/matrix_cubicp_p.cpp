#include <apps/matrix_cubicp_p.h>

MatrixCubicProver::
MatrixCubicProver(int ph, int b_size, int num_r, int input_size): Prover(ph, b_size, num_r, input_size)
{
  init_state();
}

void MatrixCubicProver::
init_state()
{
  num_bits_in_prime = 128;
  num_bits_in_input = 32;
  crypto_in_use = CRYPTO_ELGAMAL;
  png_in_use = PNG_CHACHA;
 
  Prover::init_state();
  
  hadamard_code_size = m*m*m;
  alloc_init_vec(&F1, hadamard_code_size);
  alloc_init_vec(&A, m*m);
  alloc_init_vec(&B, m*m);
  alloc_init_vec(&C, m*m);
  alloc_init_vec(&output, expansion_factor);
  alloc_init_vec(&f1_commitment, expansion_factor*hadamard_code_size);
  alloc_init_vec(&f1_q, hadamard_code_size);
  alloc_init_scalar(answer);

  F_ptrs.clear();
  F_ptrs.push_back(F1);
  f_q_ptrs.clear();
  f_q_ptrs.push_back(f1_q);
  
  num_lin_queries = 3;
  num_corr_queries = 2;
  num_ckt_queries = 2;

  find_cur_qlengths();
}

void MatrixCubicProver::
find_cur_qlengths()
{
  sizes.clear();
  hadamard_code_size = m*m*m;
  sizes.push_back(hadamard_code_size);
}

void MatrixCubicProver::
computation_matrixmult()
{
  // perform matrix multiplication
  int index, index2;
  for (int i=0; i<m; i++)
  {
    for (int j=0; j<m; j++)
    {
      index = i*m+j;
      mpz_set_ui(C[index], 0);
      for (int k=0; k<m; k++)
      {
        index2 = index*m+k;
        mpz_mul(F1[index2], A[i*m+k], B[k*m+j]);
        mpz_add(C[index], C[index], F1[index2]);
      }
    }
  }
}

//PROVER's CODE
void MatrixCubicProver::
prover_computation_commitment()
{
  // init prover
  load_vector(expansion_factor*hadamard_code_size, f1_commitment, (char *)"f1_commitment_query", FOLDER_WWW_DOWNLOAD);
  
  for (int i=0; i<batch_size; i++)
  {
    if (i == 0)
      m_comp.begin_with_init();
    else
      m_comp.begin_with_history();
    
    //for (int k=0; k<INNER_LOOP_SMALL; k++)
    {
      snprintf(scratch_str, BUFLEN-1, "input0_b_%d", i); 
      load_vector(m*m, A, scratch_str, FOLDER_WWW_DOWNLOAD);

      snprintf(scratch_str, BUFLEN-1, "input1_b_%d", i); 
      load_vector(m*m, B, scratch_str, FOLDER_WWW_DOWNLOAD);

      computation_matrixmult();

      // start saving the state
      snprintf(scratch_str, BUFLEN-1, "matrixc_b_%d", i); 
      dump_vector(m*m, C, scratch_str, FOLDER_WWW_DOWNLOAD);
    }
    m_comp.end();
    snprintf(scratch_str, BUFLEN-1, "f1_assignment_vector_b_%d", i); 
    dump_vector(m*m*m, F1, scratch_str, FOLDER_WWW_DOWNLOAD);
  }
  
  for (int i=0; i<batch_size; i++)
  {
    if (i == 0)
      m_proof_work.begin_with_init();
    else
      m_proof_work.begin_with_history();


    snprintf(scratch_str, BUFLEN-1, "f1_assignment_vector_b_%d", i); 
    load_vector(m*m*m, F1, scratch_str, FOLDER_WWW_DOWNLOAD);
   
    if (crypto_in_use == CRYPTO_PAILLIER)
      v->dot_product_enc(m*m*m, f1_commitment, F1, output[0]);
    else
      v->dot_product_enc(m*m*m, f1_commitment, F1, output[0], output[1]);
    
    snprintf(scratch_str, BUFLEN-1, "f1_commitment_answer_b_%d", i); 
    dump_vector(expansion_factor, output, scratch_str, FOLDER_WWW_DOWNLOAD);
    m_proof_work.end();
  }
}

// driver to run the phases of the verifier
int main(int argc, char **argv)
{
  int phase = 0;
  int batch_size = 100;
  int num_repetitions = 1;
  int input_size = 200;

  if (argc > 2)
  {
    parse_args(argc, argv, &phase, &batch_size, &num_repetitions, &input_size, NULL, NULL, NULL);
    MatrixCubicProver prover(phase, batch_size, num_repetitions, input_size);
    prover.handle_terminal_request();
  }
  else
  {
    MatrixCubicProver prover(phase, batch_size, num_repetitions, input_size);
    prover.handle_http_requests();
  }
  return 0;
}
