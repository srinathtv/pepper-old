#include <apps/matrix_cubicp_v.h>

MatrixCubicVerifier::MatrixCubicVerifier(int batch, int reps, int
  ip_size, int optimize_answers, char *prover_url)
  : Verifier(batch, reps, ip_size, optimize_answers, prover_url, NAME_PROVER)
{
  init_state();
}

void MatrixCubicVerifier::init_state()
{
  num_bits_in_prime = 128;
  num_bits_in_input = 32;
  crypto_in_use = CRYPTO_ELGAMAL;
  png_in_use = PNG_CHACHA;

  Verifier::init_state();

  hadamard_code_size = input_size * input_size * input_size;

  alloc_init_vec(&A, input_size * input_size);
  alloc_init_vec(&B, input_size * input_size);
  alloc_init_vec(&C, input_size*input_size);
  alloc_init_vec(&f1_commitment, expansion_factor*hadamard_code_size);
  alloc_init_vec(&f1_consistency, hadamard_code_size);
  alloc_init_vec(&f1_q1, hadamard_code_size);
  alloc_init_vec(&f1_q2, hadamard_code_size);
  alloc_init_vec(&f1_q3, hadamard_code_size);
  alloc_init_vec(&f2_q1, 2*input_size*input_size);
  alloc_init_vec(&f2_q2, 2*input_size*input_size);
  alloc_init_vec(&gamma, input_size*input_size);
  alloc_init_vec(&f1_con_coins, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&f1_answers, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&f2_answers, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&ckt_answers, 2);
  alloc_init_vec(&temp_arr, expansion_factor);

  alloc_init_scalar(a1);
  alloc_init_scalar(a2);
  alloc_init_scalar(a3);
  alloc_init_scalar(f1_s);
  alloc_init_scalar(temp); 
  alloc_init_scalar(temp2);

  // To create consistency and commitment queries.
  commitment_query_sizes.clear();
  commitment_query_sizes.push_back(hadamard_code_size);
  f_commitment_ptrs.clear();
  f_commitment_ptrs.push_back(f1_commitment);
  f_consistency_ptrs.clear();
  f_consistency_ptrs.push_back(f1_consistency);
  con_coins_ptrs.clear();
  con_coins_ptrs.push_back(f1_con_coins);
  temp_arr_ptrs.clear();
  temp_arr_ptrs.push_back(temp_arr);
  scalar_s_ptrs.clear();
  scalar_s_ptrs.push_back(&f1_s);
  scalar_a_ptrs.clear();
  scalar_a_ptrs.push_back(&a1);
  scalar_a_ptrs.push_back(&a2);
  scalar_a_ptrs.push_back(&a3);
  answers_ptrs.clear();
  answers_ptrs.push_back(f1_answers);
  answers_ptrs.push_back(f2_answers);
  L_list.clear();
  L_list.push_back(L1);
  L_list.push_back(L2);
  L_list.push_back(L3);
  Q_list.clear();
  Q_list.push_back(Q1);
  Q_list.push_back(Q2);
  C_list.clear();
  C_list.push_back(C1);
  C_list.push_back(C2);
  
  num_lin_pcp_queries = NUM_LIN_PCP_QUERIES;
}

void MatrixCubicVerifier::create_input()
{
  // as many computations as inputs
  for (int k=0; k<batch_size; k++)
  {
    v->get_random_vec(input_size * input_size, A, num_bits_in_input);
    v->get_random_vec(input_size * input_size, B, num_bits_in_input);
    
    snprintf(scratch_str, BUFLEN-1, "input0_b_%d", k); 
    dump_vector(input_size * input_size, A, scratch_str);
    send_file(scratch_str); 

    snprintf(scratch_str, BUFLEN-1, "input1_b_%d", k); 
    dump_vector(input_size * input_size, B, scratch_str);
    send_file(scratch_str); 
  }
}

void MatrixCubicVerifier::create_plain_queries()
{
  uint32_t m2 = input_size*input_size;
  
  // keeps track of #filled coins
  int f1_con_filled = -1;
  
  load_vector(hadamard_code_size, f1_consistency, (char *)"f1_consistency_query");

  for (int rho=0; rho<num_repetitions; rho++)
  {
    #ifdef STREAMING_LIN_QUERIES

    create_lin_queries(1, rho, hadamard_code_size,
      f1_consistency, &f1_con_filled, f1_con_coins);
  
    #else
    
    v->create_lin_test_queries(hadamard_code_size, f1_q1, f1_q2, f1_q3, f1_consistency,
        f1_con_filled, f1_con_coins, prime); 

    f1_con_filled += 3; 
    
    snprintf(scratch_str, BUFLEN-1, "f1_lin1_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q1, scratch_str);
    send_file(scratch_str); 
    
    snprintf(scratch_str, BUFLEN-1, "f1_lin2_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q2, scratch_str);
    send_file(scratch_str); 
    
    snprintf(scratch_str, BUFLEN-1, "f1_lin3_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q3, scratch_str);
    send_file(scratch_str); 

    #endif

    v->create_corr_test_queries_vproduct(input_size, f2_q1, f2_q2, f1_q1, f1_q2,
      f1_consistency, f1_con_filled, f1_con_coins, prime);

    f1_con_filled += 2;

    snprintf(scratch_str, BUFLEN-1, "f1_corr1_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q1, scratch_str);
    send_file(scratch_str); 
    
    snprintf(scratch_str, BUFLEN-1, "f1_corr2_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q2, scratch_str);
    send_file(scratch_str); 
  
    // compute answers to f1(q1) and f1(q2) locally now itself
    for (int b=0; b<batch_size; b++)
    {
      mpz_set_ui(a1, 0);
      mpz_set_ui(a2, 0);
      snprintf(scratch_str, BUFLEN-1, "input0_b_%d", b);
      load_vector(input_size*input_size, A, scratch_str);
      
      snprintf(scratch_str, BUFLEN-1, "input1_b_%d", b);
      load_vector(input_size*input_size, B, scratch_str);

      int index;
      mpz_set_ui(a3, 0);
      for (int k=0; k<input_size; k++)
      {
        // dot product of k^th row of A with k^th row of f2_q1
        //\sum_{j=1}{m}{A[k][j] \cdot f2_q1[k][j]}
        mpz_set_ui(a1, 0);
        mpz_set_ui(a2, 0);

        for (int j=0; j<input_size; j++)
        {
          index = j*input_size+k;
          mpz_mul(temp, A[index], f2_q1[index]);
          mpz_add(a1, a1, temp);
        }

        for (int i=0; i<input_size; i++)
        {
          index = k*input_size+i;
          mpz_mul(temp, B[index], f2_q2[index]);
          mpz_add(a2, a2, temp);
        }

        mpz_mul(temp, a1, a2);
        mpz_add(a3, a3, temp);
        mpz_mod(a3, a3, prime);
      }

      snprintf(scratch_str, BUFLEN-1, "f2_corr1_answer_b_%d_r_%d", b, rho);
      dump_scalar(a3, scratch_str);
      send_file(scratch_str); 
      
      // Not used.
      snprintf(scratch_str, BUFLEN-1, "f2_corr2_answer_b_%d_r_%d", b, rho);
      dump_scalar(a3, scratch_str);
      send_file(scratch_str); 
    }

    // circuit test
    v->get_random_vec(input_size*input_size, gamma, prime);

    for (int i=0; i<hadamard_code_size; i++)
      mpz_set_ui(f1_q1[i], 0);

    int index, index2;
    for (int i=0; i<input_size; i++)
    {
      for (int j=0; j<input_size; j++)
      {
        // add gamma[i*input_size+j] to all the cells in query
        index2 = i*input_size+j;
        for (int k=0; k<input_size; k++)
        {
          index = index2 * input_size+k;
          mpz_add(f1_q1[index], f1_q1[index], gamma[index2]);
        }
      }
    }

    for (int i=0; i<input_size*input_size*input_size; i++)
      mpz_mod(f1_q1[i], f1_q1[i], prime);


    v->create_ckt_test_queries(hadamard_code_size, f1_q1, f1_q2, f1_q3, f1_consistency,
      f1_con_filled, f1_con_coins, prime);
    f1_con_filled += 2;

    snprintf(scratch_str, BUFLEN-1, "f1_ckt1_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q2, scratch_str);
    send_file(scratch_str); 
    
    snprintf(scratch_str, BUFLEN-1, "f1_ckt2_query_r_%d", rho);
    dump_vector(hadamard_code_size, f1_q3, scratch_str);
    send_file(scratch_str); 
    
    // finally compute c
    for (int i=0; i<batch_size; i++)
    {
      snprintf(scratch_str, BUFLEN-1, "matrixc_b_%d", i);
      //recv_file(scratch_str);
      load_vector(input_size*input_size, C, scratch_str);
      
      int c_index = i * num_repetitions + rho; 
      mpz_set_ui(c_values[c_index], 0);

      for (int j=0; j<input_size*input_size; j++)
      {
        mpz_neg(temp, gamma[j]);
        mpz_mul(temp, temp, C[j]);
        mpz_add(c_values[c_index], c_values[c_index], temp);
      }
    }
  }
  dump_vector(hadamard_code_size, f1_consistency, (char *)"f1_consistency_query");
  send_file((char *)"f1_consistency_query");

  dump_vector(NUM_LIN_PCP_QUERIES*num_repetitions, f1_con_coins, (char *)"f1_con_coins");
}

void MatrixCubicVerifier::recv_outputs() {
  for (int i=0; i<batch_size; i++)
  {
    snprintf(scratch_str, BUFLEN-1, "matrixc_b_%d", i);
    recv_file(scratch_str);
  }
}

void MatrixCubicVerifier::run_correction_and_circuit_tests(uint32_t beta)
{
    for (int rho=0; rho<num_repetitions; rho++)
    {
      // Quad Correction test and Circuit test
      mpz_set(ckt_answers[0], f1_answers[rho*NUM_LIN_PCP_QUERIES + C1]);
      mpz_set(ckt_answers[1], f1_answers[rho*NUM_LIN_PCP_QUERIES + C2]);

      mpz_set_ui(temp, 1);
      bool cor1 = v->corr_test(f2_answers[rho*NUM_LIN_PCP_QUERIES + Q1], temp, f1_answers[rho*NUM_LIN_PCP_QUERIES + Q1], f1_answers[rho*NUM_LIN_PCP_QUERIES + Q2], prime);
      bool ckt2 = v->ckt_test(2, ckt_answers, c_values[beta * num_repetitions + rho], prime);

      if (false == cor1)
        cout<<"LOG: F1, F2 failed the correction test"<<endl;
      else
        cout<<"LOG: F1, F2 passed correction test"<<endl;

      if (false == ckt2)
        cout <<"LOG: F1 failed the circuit test"<<endl;
      else
        cout <<"LOG: F1 passed the circuit test"<<endl;
    }
}

// driver to run the phases of the verifier
int main(int argc, char **argv)
{
  int batch_size;
  int num_repetitions;
  int input_size;
  char prover_url[BUFLEN];
  int variant;
  int optimize_answers;

  parse_args(argc, argv, NULL, &batch_size, &num_repetitions,
    &input_size, prover_url, &variant, &optimize_answers);
  
  MatrixCubicVerifier verifier(batch_size, num_repetitions, input_size,
    optimize_answers, prover_url);
  
  if (variant == VARIANT_PEPPER)
    verifier.begin_pepper();
  else
    verifier.begin_habanero();
 
  return 0;
}
