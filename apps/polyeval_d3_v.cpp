#include <apps/polyeval_d3_v.h>

PolyEvalD3Verifier::PolyEvalD3Verifier(int batch, int reps, int ip_size,
  int optimize_answers, char *prover_url)
  : Verifier(batch, reps, ip_size, optimize_answers, prover_url, NAME_PROVER)
{
  init_state();
}

void PolyEvalD3Verifier::init_state()
{
  num_bits_in_prime = 192;
  num_bits_in_input = 32; 
  crypto_in_use= CRYPTO_ELGAMAL;
  png_in_use = PNG_CHACHA;
  
  Verifier::init_state();

  num_coefficients = (input_size*input_size*input_size + 3*input_size*input_size + 2*input_size)/6 + (input_size * input_size + 3*input_size)/2 + 1;

  alloc_init_vec(&coefficients, num_coefficients);
  alloc_init_vec(&input, input_size);
  alloc_init_vec(&f1_commitment, expansion_factor*input_size);
  alloc_init_vec(&f2_commitment, expansion_factor*input_size*input_size);
  alloc_init_vec(&f3_commitment, expansion_factor*input_size*input_size*input_size);
  alloc_init_vec(&f1_q1, input_size);
  alloc_init_vec(&f1_q2, input_size);
  alloc_init_vec(&f1_q3, input_size);
  alloc_init_vec(&f2_q1, input_size*input_size);
  alloc_init_vec(&f2_q2, input_size*input_size);
  alloc_init_vec(&f2_q3, input_size*input_size);
  alloc_init_vec(&f3_q1, input_size*input_size*input_size);
  alloc_init_vec(&f3_q2, input_size*input_size*input_size);
  alloc_init_vec(&f3_q3, input_size*input_size*input_size);
  alloc_init_vec(&f1_consistency, input_size);
  alloc_init_vec(&f2_consistency, input_size*input_size);
  alloc_init_vec(&f3_consistency, input_size*input_size*input_size);
  alloc_init_vec(&f1_con_coins, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&f2_con_coins, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&f3_con_coins, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&alpha, input_size+1); 
  alloc_init_vec(&f1_answers, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&f2_answers, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&f3_answers, num_repetitions * NUM_LIN_PCP_QUERIES);
  alloc_init_vec(&ckt_answers, 6);
  alloc_init_vec(&temp_arr, expansion_factor);
  alloc_init_vec(&temp_arr2, expansion_factor);
  alloc_init_vec(&temp_arr3, expansion_factor);
  alloc_init_scalar(a1);
  alloc_init_scalar(a2);
  alloc_init_scalar(a3);
  alloc_init_scalar(f1_s);
  alloc_init_scalar(f2_s);
  alloc_init_scalar(f3_s);
  mpz_init(temp);
  mpz_init(output);
  mpz_init(neg);
  mpz_init(neg_i);

  // To create consistency and commitment queries.
  commitment_query_sizes.clear();
  commitment_query_sizes.push_back(input_size);
  commitment_query_sizes.push_back(input_size*input_size);
  commitment_query_sizes.push_back(input_size*input_size*input_size);
  f_commitment_ptrs.clear();
  f_commitment_ptrs.push_back(f1_commitment);
  f_commitment_ptrs.push_back(f2_commitment);
  f_commitment_ptrs.push_back(f3_commitment);
  f_consistency_ptrs.clear();
  f_consistency_ptrs.push_back(f1_consistency);
  f_consistency_ptrs.push_back(f2_consistency);
  f_consistency_ptrs.push_back(f3_consistency);
  con_coins_ptrs.clear();
  con_coins_ptrs.push_back(f1_con_coins);
  con_coins_ptrs.push_back(f2_con_coins);
  con_coins_ptrs.push_back(f3_con_coins);
  temp_arr_ptrs.clear();
  temp_arr_ptrs.push_back(temp_arr);
  temp_arr_ptrs.push_back(temp_arr2);
  temp_arr_ptrs.push_back(temp_arr3);
  scalar_s_ptrs.clear();
  scalar_s_ptrs.push_back(&f1_s);
  scalar_s_ptrs.push_back(&f2_s);
  scalar_s_ptrs.push_back(&f3_s);
  scalar_a_ptrs.clear();
  scalar_a_ptrs.push_back(&a1);
  scalar_a_ptrs.push_back(&a2);
  scalar_a_ptrs.push_back(&a3);
  answers_ptrs.clear();
  answers_ptrs.push_back(f1_answers);
  answers_ptrs.push_back(f2_answers);
  answers_ptrs.push_back(f3_answers);
  L_list.clear();
  L_list.push_back(L1);
  L_list.push_back(L2);
  L_list.push_back(L3);
  Q_list.clear();
  Q_list.push_back(Q1);
  Q_list.push_back(Q2);
  Q_list.push_back(Q3);
  C_list.clear();
  C_list.push_back(C1);
  C_list.push_back(C2);
  
  num_lin_pcp_queries = NUM_LIN_PCP_QUERIES;
}

void PolyEvalD3Verifier::create_input()
{
  v->get_random_vec(num_coefficients, coefficients, num_bits_in_input);
  dump_vector(num_coefficients, coefficients, (char *)"input0");
  send_file((char *)"input0");

  // as many computations as inputs
  for (int k=0; k<batch_size; k++)
  {
    v->get_random_vec(input_size, input, num_bits_in_input);
    snprintf(scratch_str, BUFLEN-1, "input1_b_%d", k); 
    dump_vector(input_size, input, scratch_str);
    send_file(scratch_str);
  }
}

void PolyEvalD3Verifier::create_plain_queries()
{
  // keeps track of #filled coins
  int f1_con_filled = -1;
  int f2_con_filled = -1;
  int f3_con_filled = -1;
  
  load_vector(input_size, f1_consistency,
    (char *)(char *)"f1_consistency_query");
  load_vector(input_size*input_size, f2_consistency,
    (char *)"f2_consistency_query");
  load_vector(input_size*input_size*input_size, f3_consistency,
    (char *)"f3_consistency_query");
  load_vector(input_size*input_size*input_size + input_size*input_size +
    input_size+1, coefficients, (char *)"input0");

  for (int rho=0; rho<num_repetitions; rho++)
  {
#ifdef STREAMING_LIN_QUERIES

    create_lin_queries(1, rho, input_size,
      f1_consistency, &f1_con_filled, f1_con_coins);
    create_lin_queries(2, rho, input_size*input_size,
      f2_consistency, &f2_con_filled, f2_con_coins);
    create_lin_queries(3, rho, input_size*input_size*input_size,
      f3_consistency, &f3_con_filled, f3_con_coins);
      
#else

    v->create_lin_test_queries(input_size, f1_q1, f1_q2, f1_q3,
        f1_consistency, f1_con_filled, f1_con_coins, prime); 

    f1_con_filled += 3; 
    
    snprintf(scratch_str, BUFLEN-1, "f1_lin1_query_r_%d", rho);
    dump_vector(input_size, f1_q1, scratch_str);
    send_file(scratch_str);

    snprintf(scratch_str, BUFLEN-1, "f1_lin2_query_r_%d", rho);
    dump_vector(input_size, f1_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f1_lin3_query_r_%d", rho);
    dump_vector(input_size, f1_q3, scratch_str);
    send_file(scratch_str);

    v->create_lin_test_queries(input_size*input_size, f2_q1, f2_q2,
        f2_q3, f2_consistency, f2_con_filled, f2_con_coins, prime); 

    f2_con_filled += 3; 

    snprintf(scratch_str, BUFLEN-1, "f2_lin1_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_lin2_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_lin3_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q3, scratch_str);
    send_file(scratch_str);

    v->create_lin_test_queries(input_size*input_size*input_size, f3_q1,
        f3_q2, f3_q3, f3_consistency, f3_con_filled, f3_con_coins, prime); 

    f3_con_filled += 3; 

    snprintf(scratch_str, BUFLEN-1, "f3_lin1_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f3_lin2_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f3_lin3_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q3, scratch_str);
    send_file(scratch_str);
    
#endif

    v->create_corr_test_queries(input_size, f1_q1, input_size, f1_q2,
        f2_q1, f2_q2, f1_consistency, f1_consistency, f2_consistency,
        f1_con_filled, f1_con_coins, f1_con_filled+1, f1_con_coins,
        f2_con_filled, f2_con_coins, prime);

    f1_con_filled += 2;
    f2_con_filled += 2;

    snprintf(scratch_str, BUFLEN-1, "f1_corr1_query_r_%d", rho);
    dump_vector(input_size, f1_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f1_corr2_query_r_%d", rho);
    dump_vector(input_size, f1_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_corr1_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_corr2_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q2, scratch_str);
    send_file(scratch_str);


    v->create_corr_test_queries(input_size, f1_q1,
      input_size*input_size, f2_q1, f3_q1, f3_q2,
      f1_consistency, f2_consistency, f3_consistency, f1_con_filled,
      f1_con_coins, f2_con_filled, f2_con_coins, f3_con_filled,
      f3_con_coins, prime);
 
    f1_con_filled += 1;
    f2_con_filled += 1;
    f3_con_filled += 3;
    mpz_set_ui(f3_con_coins[f3_con_filled], 0);

    snprintf(scratch_str, BUFLEN-1, "f1_corr3_query_r_%d", rho);
    dump_vector(input_size, f1_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_corr3_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f3_corr1_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q1, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f3_corr2_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q2, scratch_str);
    send_file(scratch_str);

    snprintf(scratch_str, BUFLEN-1, "f3_corr3_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q3, scratch_str);
    send_file(scratch_str);

    // circuit test
    v->get_random_vec(input_size+1, alpha, prime);

    // formulate a; a = -\alpha_0 \cdot degree-2 coefficients
    mpz_neg(neg, alpha[0]);
    
    // set the query to zero first
    for (int i=0; i<input_size*input_size*input_size; i++)
    {
      mpz_set_ui(f3_q1[i], 0);
    }
 
    int index_coefficients = 0;
    int index_query = 0;
    for (int i=0; i<input_size; i++)
    {
      for (int j=0; j<=i; j++)
      {
        for (int k=0; k<=j; k++)
        {
          index_query = (i*input_size+j)*input_size+k;
          mpz_mul(f3_q1[index_query], neg, coefficients[index_coefficients]);
          mpz_mod(f3_q1[index_query], f3_q1[index_query], prime);
      
          index_coefficients++;
        }
      }
    }

    int offset = (input_size*input_size*input_size + 3*input_size*input_size + 2*input_size)/6;

    // quadratic part of circuit test query
    for (int i=0; i<input_size*input_size; i++)
    {
      mpz_set_ui(f2_q1[i], 0);
    }

    int index;
    int k = 0;
    for (int i=0; i<input_size; i++)
    {
      for (int j=0; j<=i; j++)
      {
        index = input_size*i + j;
        mpz_mul(f2_q1[index], neg, coefficients[offset+k]);
        mpz_mod(f2_q1[index], f2_q1[index], prime);
        k++;
      }
    }
    offset += (input_size * input_size + input_size)/2;

    // formulate b; b = -\alpha_0 \cdot degree-1 coefficients + [\alpha_1,
    // \alpha_2, ... , \alpha_{input_size+1}]
    for (int i=0; i<input_size; i++)
    {
      mpz_mul(f1_q1[i], neg, coefficients[offset+i]); 

      mpz_add(f1_q1[i], alpha[i+1], f1_q1[i]);
      mpz_mod(f1_q1[i], f1_q1[i], prime);
    }

    v->create_ckt_test_queries(input_size, f1_q1, f1_q2, f1_q3,
        f1_consistency, f1_con_filled, f1_con_coins, prime);
    v->create_ckt_test_queries(input_size*input_size, f2_q1, f2_q2,
        f2_q3, f2_consistency, f2_con_filled, f2_con_coins, prime);
    v->create_ckt_test_queries(input_size*input_size*input_size, f3_q1,
        f3_q2, f3_q3, f3_consistency, f3_con_filled, f3_con_coins, prime);

    // compute c
    for (int b=0; b<batch_size; b++)
    {
      snprintf(scratch_str, BUFLEN-1, "input1_b_%d", b); 
      load_vector(input_size, input, scratch_str);

      snprintf(scratch_str, BUFLEN-1, "output_b_%d", b); 
      //recv_file(scratch_str);
      load_scalar(output, scratch_str);

      int c_index = b * num_repetitions + rho; 
      mpz_set_ui(c_values[c_index], 0);

      for (int j=0; j<input_size; j++)
      {
        mpz_neg(neg_i, alpha[j+1]);
        mpz_mul(temp, neg_i, input[j]);
        mpz_add(c_values[c_index], c_values[c_index], temp);
      }
      mpz_mul(temp, neg, coefficients[num_coefficients-1]);
      mpz_add(c_values[c_index], c_values[c_index], temp);

      mpz_mul(temp, alpha[0], output);
      mpz_add(c_values[c_index], c_values[c_index], temp);
      mpz_mod(c_values[c_index], c_values[c_index], prime);
    }


    f1_con_filled += 2;
    f2_con_filled += 2;
    f3_con_filled += 2;

    snprintf(scratch_str, BUFLEN-1, "f1_ckt1_query_r_%d", rho);
    dump_vector(input_size, f1_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f1_ckt2_query_r_%d", rho);
    dump_vector(input_size, f1_q3, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_ckt1_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f2_ckt2_query_r_%d", rho);
    dump_vector(input_size*input_size, f2_q3, scratch_str);
    send_file(scratch_str);

    snprintf(scratch_str, BUFLEN-1, "f3_ckt1_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q2, scratch_str);
    send_file(scratch_str);
    
    snprintf(scratch_str, BUFLEN-1, "f3_ckt2_query_r_%d", rho);
    dump_vector(input_size*input_size*input_size, f3_q3, scratch_str);
    send_file(scratch_str);
  }
  
  dump_vector(input_size, f1_consistency, (char *)"f1_consistency_query");
  send_file((char *)"f1_consistency_query");
   
  dump_vector(input_size*input_size, f2_consistency, (char *)"f2_consistency_query");
  send_file((char *)"f2_consistency_query");

  dump_vector(input_size*input_size*input_size, f3_consistency, (char *)"f3_consistency_query");
  send_file((char *)"f3_consistency_query");

  dump_vector(NUM_LIN_PCP_QUERIES*num_repetitions, f1_con_coins, (char *)"f1_con_coins");
  dump_vector(NUM_LIN_PCP_QUERIES*num_repetitions, f2_con_coins, (char *)"f2_con_coins");
  dump_vector(NUM_LIN_PCP_QUERIES*num_repetitions, f3_con_coins, (char *)"f3_con_coins");
}

void PolyEvalD3Verifier::run_correction_and_circuit_tests(uint32_t beta)
{
    for (int rho=0; rho<num_repetitions; rho++)
    {
      // Quad Correction test and Circuit test
      mpz_set(ckt_answers[0], f1_answers[rho*NUM_LIN_PCP_QUERIES + C1]);
      mpz_set(ckt_answers[1], f1_answers[rho*NUM_LIN_PCP_QUERIES + C2]);
      mpz_set(ckt_answers[2], f2_answers[rho*NUM_LIN_PCP_QUERIES + C1]);
      mpz_set(ckt_answers[3], f2_answers[rho*NUM_LIN_PCP_QUERIES + C2]);
      mpz_set(ckt_answers[4], f3_answers[rho*NUM_LIN_PCP_QUERIES + C1]);
      mpz_set(ckt_answers[5], f3_answers[rho*NUM_LIN_PCP_QUERIES + C2]);

      bool cor1 = v->corr_test(f1_answers[rho*NUM_LIN_PCP_QUERIES + Q1], f1_answers[rho*NUM_LIN_PCP_QUERIES + Q2], f2_answers[rho*NUM_LIN_PCP_QUERIES + Q1], f2_answers[rho*NUM_LIN_PCP_QUERIES + Q2], prime);
      
      bool cor2 = v->corr_test(f1_answers[rho*NUM_LIN_PCP_QUERIES + Q3], f2_answers[rho*NUM_LIN_PCP_QUERIES + Q3], f3_answers[rho*NUM_LIN_PCP_QUERIES + Q1], f3_answers[rho*NUM_LIN_PCP_QUERIES + Q2], prime);
 
      bool ckt2 = v->ckt_test(6, ckt_answers, c_values[beta * num_repetitions + rho], prime);

      if (false == cor1)
        cout<<"LOG: F1, F2 failed the correction test"<<endl;
      else
        cout<<"LOG: F1, F2 passed correction test"<<endl;

      if (false == cor2)
        cout<<"LOG: F1, F2, F3 failed the correction test"<<endl;
      else
        cout<<"LOG: F1, F2, F3 passed correction test"<<endl;

      if (false == ckt2)
        cout <<"LOG: F1, F2, F3 failed the circuit test"<<endl;
      else
        cout <<"LOG: F1, F2, F3 passed the circuit test"<<endl;
    }
}

void PolyEvalD3Verifier::recv_outputs() {
  for (int b=0; b<batch_size; b++) {
    snprintf(scratch_str, BUFLEN-1, "output_b_%d", b); 
    recv_file(scratch_str);
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

  parse_args(argc, argv, NULL, &batch_size, &num_repetitions, &input_size,
    prover_url, &variant, &optimize_answers);
  PolyEvalD3Verifier verifier(batch_size, num_repetitions, input_size, optimize_answers, prover_url);
  
  if (variant == VARIANT_PEPPER)
    verifier.begin_pepper();
  else
    verifier.begin_habanero();
  return 0;
}
