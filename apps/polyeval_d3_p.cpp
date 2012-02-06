#include <apps/polyeval_d3_p.h>

PolyEvalD3Prover::
PolyEvalD3Prover(int ph, int b_size, int num_r, int input_size): Prover(ph, b_size, num_r, input_size)
{
  init_state();
}

void PolyEvalD3Prover::
init_state()
{
  num_bits_in_prime = 192;
  num_bits_in_input = 32; 
  crypto_in_use= CRYPTO_ELGAMAL;
  png_in_use = PNG_CHACHA;

  Prover::init_state();
  num_coefficients = (m*m*m + 3*m*m + 2*m)/6 + (m * m + 3*m)/2 + 1;

  alloc_init_vec(&F1, m);
  alloc_init_vec(&F2, m*m);
  alloc_init_vec(&F3, m*m*m);
  alloc_init_vec(&output, expansion_factor);
  alloc_init_vec(&variables, m);
  alloc_init_vec(&coefficients, num_coefficients);
  alloc_init_vec(&f1_q, m);
  alloc_init_vec(&F1, m);
  alloc_init_vec(&f1_commitment, expansion_factor*m);
  alloc_init_vec(&f1_consistency, m);
  alloc_init_vec(&f2_q, m*m);
  alloc_init_vec(&F2, m*m);
  alloc_init_vec(&f2_commitment, expansion_factor*m*m);
  alloc_init_vec(&f2_consistency, m*m);
  alloc_init_vec(&f3_q, m*m*m); 
  alloc_init_vec(&F3, m*m*m); 
  alloc_init_vec(&f3_commitment, expansion_factor*m*m*m); 
  alloc_init_vec(&f3_consistency, m*m*m); 
  alloc_init_scalar(answer);
  alloc_init_scalar(temp);
  alloc_init_scalar(temp2);
  
  F_ptrs.clear();
  F_ptrs.push_back(F1);
  F_ptrs.push_back(F2);
  F_ptrs.push_back(F3);
  f_q_ptrs.clear();
  f_q_ptrs.push_back(f1_q);
  f_q_ptrs.push_back(f2_q);
  f_q_ptrs.push_back(f3_q);

  num_lin_queries = 3;
  num_corr_queries = 3;
  num_ckt_queries = 2;
  
  find_cur_qlengths();
}

void PolyEvalD3Prover::
find_cur_qlengths()
{
  num_coefficients = (m*m*m + 3*m*m + 2*m)/6 + (m * m + 3*m)/2 + 1;
  sizes.clear();
  sizes.push_back(m);
  sizes.push_back(m*m);
  sizes.push_back(m*m*m);
}

// COMPUTATION
void PolyEvalD3Prover::
computation_polyeval(mpz_t output)
{
  // perform polynomial evaluation
  // first, compute the cubic assignment, F3 = \op{m}{m}{m}
  // then, compute the quadratic assignment, F2 = \op{m}{m}
  int index = 0, index2 = 0, index3 = 0;

  // compute F1 and F2
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
  
  // next compute F3 and partial output
  mpz_set_ui(output, 0);
  index2 = 0; index3 = 0;
  for (int i=0; i<m; i++)
  {
    for (int j=0; j<=i; j++)
    {
      index = m*i + j;
      for (int k=0; k<=j; k++)
      {
        mpz_mul(temp, F2[index], variables[k]);
        
        // partial output
        mpz_mul(temp2, coefficients[index3], temp);
        mpz_add(output, output, temp2);     
        index3++;

        index2 = (i*m+j)*m+k;
        mpz_set(F3[index2], temp);

        index2 = (j*m+i)*m+k;
        mpz_set(F3[index2], temp);

        index2 = (j*m+k)*m+i;
        mpz_set(F3[index2], temp);
 
        index2 = (k*m+j)*m+i;
        mpz_set(F3[index2], temp);

        index2 = (k*m+i)*m+j;
        mpz_set(F3[index2], temp);

        index2 = (i*m+k)*m+j;
        mpz_set(F3[index2], temp);
      }
    }
  }

  // now compute the output; 
  for (int i=0; i<m; i++)
  {
    for (int j=0; j<=i; j++)
    {
      int index = m*i+j;
      mpz_mul(temp, coefficients[index3], F2[index]);
      mpz_add(output, output, temp);
      index3++;
    }
  }
 
  // now the linear term
  for (int i=0; i<m; i++)
  {
    mpz_mul(temp, coefficients[index3+i], F1[i]);
    mpz_add(output, output, temp);
  }
  
  index3 += m;

  // now the constant term
  mpz_add(output, output, coefficients[index3]);
  mpz_mod(output, output, prime);
}

//PROVER's CODE
void PolyEvalD3Prover::
prover_computation_commitment()
{
  load_vector(expansion_factor*m, f1_commitment, (char *)"f1_commitment_query", FOLDER_WWW_DOWNLOAD);
  load_vector(expansion_factor*m*m, f2_commitment, (char *)"f2_commitment_query", FOLDER_WWW_DOWNLOAD);
  load_vector(expansion_factor*m*m*m, f3_commitment, (char *)"f3_commitment_query", FOLDER_WWW_DOWNLOAD);
  
  m_comp.begin_with_init();
  //for (int k=0; k<INNER_LOOP_SMALL; k++)
  load_vector(num_coefficients, coefficients, (char *)"input0", FOLDER_WWW_DOWNLOAD);
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

    snprintf(scratch_str, BUFLEN-1, "f3_assignment_vector_b_%d", i); 
    dump_vector(m*m*m, F3, scratch_str, FOLDER_WWW_DOWNLOAD);
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

    snprintf(scratch_str, BUFLEN-1, "f3_assignment_vector_b_%d", i); 
    load_vector(m*m*m, F3, scratch_str, FOLDER_WWW_DOWNLOAD);
    
    if (crypto_in_use == CRYPTO_PAILLIER)
      v->dot_product_enc(m, f1_commitment, F1, output[0]);
    else
      v->dot_product_enc(m, f1_commitment, F1, output[0], output[1]);
    
    snprintf(scratch_str, BUFLEN-1, "f1_commitment_answer_b_%d", i); 
    dump_vector(expansion_factor, output, scratch_str, FOLDER_WWW_DOWNLOAD);
  
    if (crypto_in_use == CRYPTO_PAILLIER)
      v->dot_product_enc(m*m, f2_commitment, F2, output[0]);
    else
      v->dot_product_enc(m*m, f2_commitment, F2, output[0], output[1]);

    snprintf(scratch_str, BUFLEN-1, "f2_commitment_answer_b_%d", i); 
    dump_vector(expansion_factor, output, scratch_str, FOLDER_WWW_DOWNLOAD);
  
    if (crypto_in_use == CRYPTO_PAILLIER)
      v->dot_product_enc(m*m*m, f3_commitment, F3, output[0]);
    else
      v->dot_product_enc(m*m*m, f3_commitment, F3, output[0], output[1]);

    snprintf(scratch_str, BUFLEN-1, "f3_commitment_answer_b_%d", i); 
    dump_vector(expansion_factor, output, scratch_str, FOLDER_WWW_DOWNLOAD); 
    
    m_proof_work.end();
  }
}

// driver to run the phases of the verifier
int main(int argc, char **argv)
{
  int phase = 0;
  int batch_size = 1;
  int num_repetitions = 70;
  int input_size = 100;

  if (argc > 2)
  {
    parse_args(argc, argv, &phase, &batch_size, &num_repetitions, &input_size, NULL, NULL, NULL);
    PolyEvalD3Prover prover(phase, batch_size, num_repetitions, input_size);
    prover.handle_terminal_request();
  }
  else
  {
    PolyEvalD3Prover prover(phase, batch_size, num_repetitions, input_size);
    prover.handle_http_requests();
  }
  return 0;
}
