#include <apps/polyeval_d2_p.h>

PolyEvalD2Prover::
PolyEvalD2Prover(int ph, int b_size, int num_r, int input_size): Prover(ph, b_size, num_r, input_size)
{
  init_state();
}

void PolyEvalD2Prover::
init_state()
{
  num_bits_in_prime = 128;
  num_bits_in_input = 32;
  crypto_in_use = CRYPTO_ELGAMAL;
  png_in_use = PNG_CHACHA;
  
  Prover::init_state();
  
  alloc_init_vec(&F1, m);
  alloc_init_vec(&F2, m*m);
  alloc_init_vec(&output, expansion_factor);
  alloc_init_vec(&variables, m);
  alloc_init_vec(&coefficients, m*m+m+1);
  alloc_init_vec(&f1_commitment, expansion_factor*m);
  alloc_init_vec(&f1_consistency, expansion_factor*m);
  alloc_init_vec(&f1_q, m);
  alloc_init_vec(&f2_commitment, expansion_factor*m*m);
  alloc_init_vec(&f2_consistency, expansion_factor*m*m);
  alloc_init_vec(&f2_q, m*m);
  alloc_init_scalar(answer);

  F_ptrs.clear();
  F_ptrs.push_back(F1);
  F_ptrs.push_back(F2);
  f_q_ptrs.clear();
  f_q_ptrs.push_back(f1_q);
  f_q_ptrs.push_back(f2_q);
  
  num_lin_queries = 3;
  num_corr_queries = 2;
  num_ckt_queries = 2;

  find_cur_qlengths();
}

void PolyEvalD2Prover::
find_cur_qlengths()
{
  sizes.clear();
  sizes.push_back(m);
  sizes.push_back(m*m);  
}

// COMPUTATION
void PolyEvalD2Prover::
computation_polyeval(mpz_t output)
{
  // perform polynomial evaluation
  // first, compute the quadratic assignment, F2 = \op{m}{m}
  int index, index2;
  for (int i=0; i<m; i++)
  {
    mpz_set(F1[i], variables[i]);
    for (int j=0; j<=i; j++)
    {
      index = m*i+j;
      mpz_mul(F2[index], variables[i], variables[j]);
    }
  }
  for (int i=0; i<m; i++)
  {
    for (int j=i+1; j<m; j++)
    {
      index = m*i + j;
      index2 = m*j+i;
      mpz_set(F2[index], F2[index2]);
    }
  }

  // now compute the output; first the quadratic term
  mpz_t temp;
  mpz_init(temp);
  int k = 0;
  for (int i=0; i<m; i++)
  {
    for (int j=0; j<=i; j++)
    {
      int index = m*i+j;
      mpz_mul(temp, coefficients[k], F2[index]);
      mpz_add(output, output, temp);
      k++;
    }
  }
  
  // now the linear term
  for (int i=0; i<m; i++)
  {
    mpz_mul(temp, coefficients[k], F1[i]);
    mpz_add(output, output, temp);
    k++;
  }
  
  // now the constant term
  mpz_add(output, output, coefficients[k]);
  mpz_mod(output, output, prime);
}

//PROVER's CODE
void PolyEvalD2Prover::
prover_computation_commitment()
{
  // init prover
  uint32_t s1 = m;
  uint32_t s2 = m*m;

  // execute the computation
  load_vector(expansion_factor*m, f1_commitment, (char *)"f1_commitment_query", FOLDER_WWW_DOWNLOAD);
  load_vector(expansion_factor*m*m, f2_commitment, (char *)"f2_commitment_query", FOLDER_WWW_DOWNLOAD);
  
  m_comp.begin_with_init();
  load_vector((m*m+3*m)/2+1, coefficients, (char *)"input0", FOLDER_WWW_DOWNLOAD);
  m_comp.end();

  for (int i=0; i<batch_size; i++)
  {
    m_comp.begin_with_history(); 
    //for (int k=0; k<INNER_LOOP_SMALL; k++)
    {
      snprintf(scratch_str, BUFLEN-1, "input1_b_%d", i); 
      load_vector(m, variables, scratch_str, FOLDER_WWW_DOWNLOAD);

      for (int j=0; j<expansion_factor; j++)
        mpz_set_ui(output[j], 0);

      computation_polyeval(output[0]);

      // start saving the state
      snprintf(scratch_str, BUFLEN-1, "output_b_%d", i); 
      dump_scalar(output[0], scratch_str, FOLDER_WWW_DOWNLOAD);
    }
    m_comp.end();
    
    snprintf(scratch_str, BUFLEN-1, "f1_assignment_vector_b_%d", i); 
    dump_vector(m, F1, scratch_str, FOLDER_WWW_DOWNLOAD);
    
    snprintf(scratch_str, BUFLEN-1, "f2_assignment_vector_b_%d", i); 
    dump_vector(m*m, F2, scratch_str, FOLDER_WWW_DOWNLOAD);
  }

  for (int i=0; i<batch_size; i++)
  { 
    if (i == 0)
      m_proof_work.begin_with_init();
    else
      m_proof_work.begin_with_history();

    snprintf(scratch_str, BUFLEN-1, "f1_assignment_vector_b_%d", i); 
    load_vector(m, F1, scratch_str, FOLDER_WWW_DOWNLOAD);
    
    snprintf(scratch_str, BUFLEN-1, "f2_assignment_vector_b_%d", i); 
    load_vector(m*m, F2, scratch_str, FOLDER_WWW_DOWNLOAD);

    if (crypto_in_use == CRYPTO_PAILLIER)
      v->dot_product_enc(m, f1_commitment, F1, output[0]);
    else if (crypto_in_use == CRYPTO_ELGAMAL)
      v->dot_product_enc(m, f1_commitment, F1, output[0], output[1]);
    
    snprintf(scratch_str, BUFLEN-1, "f1_commitment_answer_b_%d", i); 
    dump_vector(expansion_factor, output, scratch_str, FOLDER_WWW_DOWNLOAD);
  
    if (crypto_in_use == CRYPTO_PAILLIER)
      v->dot_product_enc(m*m, f2_commitment, F2, output[0]);
    else if (crypto_in_use == CRYPTO_ELGAMAL)
      v->dot_product_enc(m*m, f2_commitment, F2, output[0], output[1]);
    
    snprintf(scratch_str, BUFLEN-1, "f2_commitment_answer_b_%d", i); 
    dump_vector(expansion_factor, output, scratch_str, FOLDER_WWW_DOWNLOAD);
    m_proof_work.end();
  }
}

// driver to run the phases of the verifier
int main(int argc, char **argv)
{
  int phase = 0;
  int batch_size = 100;
  int num_repetitions = 70;
  int input_size = 500;

  if (argc > 2)
  {
    parse_args(argc, argv, &phase, &batch_size, &num_repetitions, &input_size, NULL, NULL, NULL);
    PolyEvalD2Prover prover(phase, batch_size, num_repetitions, input_size);
    prover.handle_terminal_request();
  }
  else
  {
    PolyEvalD2Prover prover(phase, batch_size, num_repetitions, input_size);
    prover.handle_http_requests();
  }
  return 0;
}
