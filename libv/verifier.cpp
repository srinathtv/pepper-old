#include <libv/verifier.h>
#include <sstream>

Verifier::Verifier(int batch, int reps, int ip_size, int opt_answers,
                   char *prover_url, const char *prover_name) {
  batch_size = batch;
  num_repetitions = reps;
  input_size = ip_size;
  optimize_answers = opt_answers;
  alloc_init_vec(&c_values, batch_size * num_repetitions);
  
  if (prover_url[0] != '\0')
    init_server_variables(prover_url, prover_name);
}

Verifier::~Verifier(void) {
  delete v;
}

void Verifier::init_state() {
  mpz_init(prime);
  snprintf(scratch_str, BUFLEN - 1, "prime_%d.txt", num_bits_in_prime);
  load_txt_scalar(prime, scratch_str, const_cast<char *>("static_state"));
  if (crypto_in_use == CRYPTO_ELGAMAL)
    expansion_factor = 2;
  else
    expansion_factor = 1;

  v = new Venezia(ROLE_VERIFIER, crypto_in_use, png_in_use);
}

void Verifier::init_server_variables(char *prover_url,
                                     const char *prover_name) {
  int remaining = strlen(SERVICE_UPLOAD_NAME) + 1;

  snprintf(prover_upload_url, BUFLEN-1, "%s%s", prover_url,
           SERVICE_UPLOAD_NAME);
  snprintf(prover_download_url, BUFLEN-1, "%s%s", prover_url,
          SERVICE_DOWNLOAD_NAME);
  snprintf(prover_query_url, BUFLEN-1, "%s%s", prover_url, prover_name);
  curl = new CurlUtil();
}

void Verifier::send_file(char *file_name) {
  snprintf(full_file_name, BUFLEN - 1, "computation_state/%s", file_name);
  curl->send_file(full_file_name, prover_upload_url);
}

void Verifier::recv_file(const char *file_name) {
  snprintf(full_file_name, BUFLEN - 1, "computation_state/%s", file_name);
  snprintf(download_url, BUFLEN - 1, "%s?file=%s", prover_download_url,
           file_name);
  curl->recv_file(full_file_name, download_url);
}

void Verifier::invoke_prover(int prover_phase) {
  // construct the GET url with the parameters
  // phase=1&reps=1&batch_size=1&m=2
  snprintf(full_url, BUFLEN - 1,
           "%s?phase=%d&batch_size=%d&reps=%d&m=%d&opt=%d",
           prover_query_url, prover_phase, batch_size, num_repetitions,
           input_size, optimize_answers);
  // wait till the prover finishes its work
  curl->get(full_url);
}

void Verifier::create_lin_queries(int f_num, int rho, int inp_size,
                                  mpz_t * f_consistency, int *f_con_filled,
                                  mpz_t * f_con_coins) {
  FILE *l1, *l2, *l3;

  snprintf(scratch_str, BUFLEN - 1, "f%d_lin1_query_r_%d", f_num, rho);
  create_file(&l1, scratch_str, const_cast<char *>("wb"), NULL);
  snprintf(scratch_str, BUFLEN - 1, "f%d_lin2_query_r_%d", f_num, rho);
  create_file(&l2, scratch_str, const_cast<char *>("wb"), NULL);
  snprintf(scratch_str, BUFLEN - 1, "f%d_lin3_query_r_%d", f_num, rho);
  create_file(&l3, scratch_str, const_cast<char *>("wb"), NULL);

  v->create_lin_test_queries_streaming(inp_size, l1, l2, l3,
                                       f_consistency, *f_con_filled,
                                       f_con_coins, prime);

  (*f_con_filled) = (*f_con_filled) + 3;

  fclose(l1);
  fclose(l2);
  fclose(l3);

  snprintf(scratch_str, BUFLEN - 1, "f%d_lin1_query_r_%d", f_num, rho);
  send_file(scratch_str);
  snprintf(scratch_str, BUFLEN - 1, "f%d_lin2_query_r_%d", f_num, rho);
  send_file(scratch_str);
  snprintf(scratch_str, BUFLEN - 1, "f%d_lin3_query_r_%d", f_num, rho);
  send_file(scratch_str);
}

void Verifier::create_commitment_query() {
  mpz_t *f_commitment, *f_consistency;

  string commitment_str = "fX_commitment_query";

  string consistency_str = "fX_consistency_query";

  vector < uint32_t >::const_iterator it = commitment_query_sizes.begin();
  for (uint32_t i = 0; i < commitment_query_sizes.size(); i++) {
    v->create_commitment_query(commitment_query_sizes[i],
                               f_commitment_ptrs[i], f_consistency_ptrs[i],
                               prime);

    commitment_str[1] = '0' + (i + 1);
    consistency_str[1] = '0' + (i + 1);

    dump_vector(expansion_factor * (commitment_query_sizes[i]),
                f_commitment_ptrs[i],
                const_cast<char *>(commitment_str.c_str()));
    send_file(const_cast<char *>(commitment_str.c_str()));

    dump_vector(commitment_query_sizes[i], f_consistency_ptrs[i],
                const_cast<char *>(consistency_str.c_str()));
  }
}

void Verifier::load_consistency_query() {
  mpz_t *f_consistency;

  string consistency_str = "fX_consistency_query";

  vector < uint32_t >::const_iterator it = commitment_query_sizes.begin();
  for (uint32_t i = 0; i < commitment_query_sizes.size(); i++) {
    consistency_str[1] = '0' + (i + 1);

    load_vector(commitment_query_sizes[i], f_consistency_ptrs[i],
                const_cast<char *>(consistency_str.c_str()));
  }
}

void Verifier::recv_com_answers() {
  for (int beta = 0; beta < batch_size; beta++) {
    cout << endl << "LOG: Batch " << beta << endl;

    string commitment_answer_str = "fX_commitment_answer_b_%d";

    for (uint32_t i = 0; i < temp_arr_ptrs.size(); i++) {
      commitment_answer_str[1] = '0' + (i + 1);
      snprintf(scratch_str, BUFLEN - 1, commitment_answer_str.c_str(),
               beta);
      recv_file(scratch_str);
    }
  }
}

void Verifier::run_tests() {
  // Consistency test
  string con_coins_str = "fX_con_coins";

  for (uint32_t i = 0; i < con_coins_ptrs.size(); i++) {
    con_coins_str[1] = '0' + (i + 1);
    load_vector(num_repetitions * num_lin_pcp_queries, con_coins_ptrs[i],
                const_cast<char *>(con_coins_str.c_str()));
  }

  for (int beta = 0; beta < batch_size; beta++) {
    cout << endl << "LOG: Batch " << beta << endl;

    string commitment_answer_str = "fX_commitment_answer_b_%d";

    for (uint32_t i = 0; i < temp_arr_ptrs.size(); i++) {
      commitment_answer_str[1] = '0' + (i + 1);
      snprintf(scratch_str, BUFLEN - 1, commitment_answer_str.c_str(),
               beta);
      load_vector(expansion_factor, temp_arr_ptrs[i], scratch_str);
    }

    if (crypto_in_use == CRYPTO_PAILLIER) {
      for (uint32_t i = 0; i < temp_arr_ptrs.size(); i++)
        v->paillier_dec(*(scalar_s_ptrs[i]), temp_arr_ptrs[i][0]);
      for (uint32_t i = 0; i < scalar_s_ptrs.size(); i++)
        mpz_mod(*(scalar_s_ptrs[i]), *(scalar_s_ptrs[i]), prime);
    } else if (crypto_in_use == CRYPTO_ELGAMAL) {
      for (uint32_t i = 0; i < temp_arr_ptrs.size(); i++) {
        v->elgamal_dec(*(scalar_s_ptrs[i]), temp_arr_ptrs[i][0],
                       temp_arr_ptrs[i][1]);
      }
    }

    FILE *fp = NULL;

    if (optimize_answers) {
      char f_name[BUFLEN];

      snprintf(f_name, BUFLEN - 1, "answers_%d", beta + 1);
      recv_file(f_name);
      snprintf(f_name, BUFLEN - 1, "computation_state/answers_%d",
               beta + 1);
      fp = fopen(f_name, "rb");
      if (fp == NULL) {
        printf("Failed to open %s file for reading.", f_name);
        exit(1);
      }
    }

    string consistency_answer_str = "fX_consistency_answer_b_%d";

    for (uint32_t i = 0; i < scalar_a_ptrs.size(); i++) {
      consistency_answer_str[1] = '0' + (i + 1);

      snprintf(scratch_str, BUFLEN - 1, consistency_answer_str.c_str(),
               beta);
      if (!optimize_answers) {
        recv_file(scratch_str);
        load_scalar(*(scalar_a_ptrs[i]), scratch_str);
      } else {
        size_t bytes = mpz_inp_raw(*(scalar_a_ptrs[i]), fp);

        fseek(fp, bytes, SEEK_CUR);
      }
    }

    for (int rho = 0; rho < num_repetitions; rho++) {
      // linearity test answers
      string lin_answer_str = "fX_linX_answer_b_%d_r_%d";

      for (uint32_t i = 0; i < answers_ptrs.size(); i++) {
        lin_answer_str[1] = '0' + (i + 1);

        for (uint32_t j = 0; j < L_list.size(); j++) {
          lin_answer_str[6] = '0' + (j + 1);
          snprintf(scratch_str, BUFLEN - 1, lin_answer_str.c_str(), beta,
                   rho);
          // L_list -> L1, L2, L3
          if (!optimize_answers) {
            recv_file(scratch_str);
            load_scalar(answers_ptrs[i]
                        [rho * num_lin_pcp_queries + L_list[j]],
                        scratch_str);
          } else {
            size_t bytes =
              mpz_inp_raw(answers_ptrs[i]
                          [rho * num_lin_pcp_queries + L_list[j]], fp);
            fseek(fp, bytes, SEEK_CUR);
          }
        }
      }

      // correction test answers
      string corr_answer_str = "fX_corrX_answer_b_%d_r_%d";

      for (uint32_t i = 0; i < answers_ptrs.size(); i++) {
        corr_answer_str[1] = '0' + (i + 1);

        for (uint32_t j = 0; j < Q_list.size(); j++) {
          corr_answer_str[7] = '0' + (j + 1);
          snprintf(scratch_str, BUFLEN - 1, corr_answer_str.c_str(), beta,
                   rho);
          // Q_list -> Q1, Q2, Q3
          if (!optimize_answers) {
            recv_file(scratch_str);
            load_scalar(answers_ptrs[i]
                        [rho * num_lin_pcp_queries + Q_list[j]],
                        scratch_str);
          } else {
            size_t bytes =
              mpz_inp_raw(answers_ptrs[i]
                          [rho * num_lin_pcp_queries + Q_list[j]], fp);
            fseek(fp, bytes, SEEK_CUR);
          }
        }
      }

      // circuit test answers
      string ckt_answer_str = "fX_cktX_answer_b_%d_r_%d";

      for (uint32_t i = 0; i < answers_ptrs.size(); i++) {
        ckt_answer_str[1] = '0' + (i + 1);

        for (uint32_t j = 0; j < C_list.size(); j++) {
          ckt_answer_str[6] = '0' + (j + 1);
          snprintf(scratch_str, BUFLEN - 1, ckt_answer_str.c_str(), beta,
                   rho);
          // C_list -> C1, C2
          if (!optimize_answers) {
            recv_file(scratch_str);
            load_scalar(answers_ptrs[i]
                        [rho * num_lin_pcp_queries + C_list[j]],
                        scratch_str);
          } else {
            size_t bytes =
              mpz_inp_raw(answers_ptrs[i]
                          [rho * num_lin_pcp_queries + C_list[j]], fp);
            fseek(fp, bytes, SEEK_CUR);
          }
        }
      }
    }

    if (fp != NULL)
      fclose(fp);

    // consistency test
    bool con = true;

    string msg = "";

    for (uint32_t i = 0; i < con_coins_ptrs.size(); i++) {
      con = con
        && (v->
            consistency_test(num_repetitions * num_lin_pcp_queries,
                             *(scalar_a_ptrs[i]), *(scalar_s_ptrs[i]),
                             answers_ptrs[i], con_coins_ptrs[i], prime));
      std::ostringstream oss;
      oss << (i + 1);
      msg += "F" + oss.str() + ", ";
    }

    if (false == con)
      cout << "LOG: " << msg << "failed the consistency test" << endl;
    else
      cout << "LOG: " << msg << "passed the consistency test" << endl;

    // Linearity test
    for (int rho = 0; rho < num_repetitions; rho++) {
      string results = "";

      for (uint32_t i = 0; i < answers_ptrs.size(); i++) {
        bool lin =
          v->
          lin_test(answers_ptrs[i][rho * num_lin_pcp_queries + L_list[0]],
                   answers_ptrs[i][rho * num_lin_pcp_queries + L_list[1]],
                   answers_ptrs[i][rho * num_lin_pcp_queries + L_list[2]],
                   prime);
        std::ostringstream oss;
        oss << (i + 1);
        if (false == lin)
          results += "LOG: F" + oss.str() + " failed lin test\n";
        else
          results += "LOG: F" + oss.str() + " passed lin test\n";
      }
      cout << results;
    }
    run_correction_and_circuit_tests(beta);
  }
}

void Verifier::begin_pepper() {
  Measurement m;

  m.begin_with_init();
  create_commitment_query();
  m.end();
  cout << "v_commitmentq_create " << m.get_ru_elapsed_time() << endl;
  begin_habanero();
}

void Verifier::begin_habanero() {
  Measurement m;

  cout << "batch_size " << batch_size << endl;
  cout << "num_reps " << num_repetitions << endl;
  cout << "input_size " << input_size << endl;
  cout << "num_bits_in_input " << num_bits_in_input << endl;
  cout << "num_bits_in_prime " << num_bits_in_prime << endl;

  create_input();

  invoke_prover(PHASE_PROVER_COMMITMENT);
  recv_com_answers();
  recv_outputs();
  load_consistency_query();

  m.begin_with_init();
  create_plain_queries();
  m.end();
  cout << "v_plainq_create " << m.get_ru_elapsed_time() << endl;

  invoke_prover(PHASE_PROVER_PCP);

  m.begin_with_init();
  run_tests();
  m.end();
  cout << "v_run_pcp_tests " << m.get_ru_elapsed_time() << endl;
}
