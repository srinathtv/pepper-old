#include <libv/prover.h>
#include <stdio.h>

void Prover::init_state() {
  mpz_init(prime);

  if (crypto_in_use == CRYPTO_ELGAMAL)
    expansion_factor = 2;
  else
    expansion_factor = 1;

  snprintf(scratch_str, BUFLEN - 1, "prime_%d.txt", num_bits_in_prime);
  load_txt_scalar(prime, scratch_str, const_cast<char *>("static_state"));

  v = new Venezia(ROLE_PROVER, crypto_in_use, png_in_use);
}

void Prover::prover_answer_query(uint32_t size, mpz_t * q, char *q_name,
                                 mpz_t * assignment, mpz_t answer,
                                 mpz_t prime, char *a_name, FILE * fp) {
  load_vector(size, q, q_name, FOLDER_WWW_DOWNLOAD);
  v->dot_product(size, q, assignment, answer, prime);

  if (!optimize_answers) {
    dump_scalar(answer, a_name, FOLDER_WWW_DOWNLOAD);
  } else {
    size_t bytes = mpz_out_raw(FCGI_ToFILE(fp), answer);

    fseek(fp, bytes, SEEK_CUR);
  }
}

void Prover::prover_answer_queries() {
  for (int i = 0; i < batch_size; i++) {
    string assignment_vector = "fX_assignment_vector_b_%d";

    for (uint32_t j = 0; j < F_ptrs.size(); j++) {
      assignment_vector[1] = '0' + (j + 1);
      snprintf(scratch_str, BUFLEN - 1, assignment_vector.c_str(), i);
      load_vector(sizes[j], F_ptrs[j], scratch_str, FOLDER_WWW_DOWNLOAD);
    }

    FILE *fp = NULL;

    if (optimize_answers) {
      char f_name[BUFLEN];

      snprintf(f_name, BUFLEN - 1, "%s/answers_%d", FOLDER_WWW_DOWNLOAD,
               i + 1);
      fp = fopen(f_name, "wb");
      if (fp == NULL) {
        printf("Prover: could not create file %s.", f_name);
        exit(1);
      }
    }
    // consistency query
    string consistency_query = "fX_consistency_query";

    string consistency_answer = "fX_consistency_answer_b_%d";

    for (uint32_t j = 0; j < F_ptrs.size(); j++) {
      consistency_query[1] = '0' + (j + 1);
      consistency_answer[1] = '0' + (j + 1);
      snprintf(scratch_str, BUFLEN - 1, consistency_query.c_str());
      snprintf(scratch_str2, BUFLEN - 1, consistency_answer.c_str(), i);
      prover_answer_query(sizes[j], f_q_ptrs[j], scratch_str, F_ptrs[j],
                          answer, prime, scratch_str2, fp);
    }

    for (int rho = 0; rho < num_repetitions; rho++) {
      // lin test queries
      string lin_query = "fX_linX_query_r_%d";

      string lin_answer = "fX_linX_answer_b_%d_r_%d";

      for (uint32_t j = 0; j < F_ptrs.size(); j++) {
        lin_query[1] = '0' + (j + 1);
        lin_answer[1] = '0' + (j + 1);
        for (int k = 0; k < num_lin_queries; k++) {
          lin_query[6] = '0' + (k + 1);
          lin_answer[6] = '0' + (k + 1);
          snprintf(scratch_str, BUFLEN - 1, lin_query.c_str(), rho);
          snprintf(scratch_str2, BUFLEN - 1, lin_answer.c_str(), i, rho);
          prover_answer_query(sizes[j], f_q_ptrs[j], scratch_str,
                              F_ptrs[j], answer, prime, scratch_str2, fp);
        }
      }

      // quad corr test queries
      string corr_query = "fX_corrX_query_r_%d";

      string corr_answer = "fX_corrX_answer_b_%d_r_%d";

      for (uint32_t j = 0; j < F_ptrs.size(); j++) {
        corr_query[1] = '0' + (j + 1);
        corr_answer[1] = '0' + (j + 1);
        for (int k = 0; k < num_corr_queries; k++) {
          corr_query[7] = '0' + (k + 1);
          corr_answer[7] = '0' + (k + 1);
          snprintf(scratch_str, BUFLEN - 1, corr_query.c_str(), rho);
          snprintf(scratch_str2, BUFLEN - 1, corr_answer.c_str(), i, rho);
          prover_answer_query(sizes[j], f_q_ptrs[j], scratch_str,
                              F_ptrs[j], answer, prime, scratch_str2, fp);
        }
      }

      // ckt test queries
      string ckt_query = "fX_cktX_query_r_%d";

      string ckt_answer = "fX_cktX_answer_b_%d_r_%d";

      for (uint32_t j = 0; j < F_ptrs.size(); j++) {
        ckt_query[1] = '0' + (j + 1);
        ckt_answer[1] = '0' + (j + 1);
        for (int k = 0; k < num_ckt_queries; k++) {
          ckt_query[6] = '0' + (k + 1);
          ckt_answer[6] = '0' + (k + 1);
          snprintf(scratch_str, BUFLEN - 1, ckt_query.c_str(), rho);
          snprintf(scratch_str2, BUFLEN - 1, ckt_answer.c_str(), i, rho);
          prover_answer_query(sizes[j], f_q_ptrs[j], scratch_str,
                              F_ptrs[j], answer, prime, scratch_str2, fp);
        }
      }
    }

    if (fp != NULL)
      fclose(fp);
  }
}

Prover::Prover(int ph, int b_size, int num_r, int i_size) {
  phase = ph;
  batch_size = b_size;
  num_repetitions = num_r;
  m = i_size;
}

// driver to to run the phases of the prover
void Prover::handle_terminal_request() {
  switch (phase) {
    case PHASE_PROVER_COMMITMENT:
      prover_computation_commitment();
      break;

    case PHASE_PROVER_PCP:
      m_proof_work.begin_with_init();
      prover_answer_queries();
      m_proof_work.end();
      break;

    default:
      printf("Undefined prover phase %d", phase);
  }
}

void Prover::handle_http_requests() {
  while (FCGI_Accept() >= 0) {
    printf("Content-type: text/html\r\n" "\r\n");
    parse_http_args(getenv("QUERY_STRING"), &phase, &batch_size,
                    &num_repetitions, &m, &optimize_answers);
    find_cur_qlengths();

    handle_terminal_request();

    // print out the measurement stuff here.
    if (phase == PHASE_PROVER_COMMITMENT) {
      printf("computation %f\n", m_comp.get_ru_elapsed_time());
      printf("p_commitment_answer %f\n",
             m_proof_work.get_ru_elapsed_time());
      printf("p_commitment_answer_par %f\n",
             m_proof_work.get_papi_elapsed_time());
    } else {
      printf("p_answer_plainq %f\n", m_proof_work.get_ru_elapsed_time());
    }
  }
}
