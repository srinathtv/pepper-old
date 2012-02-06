#ifndef CODE_PEPPER_LIBV_VERIFIER_H_
#define CODE_PEPPER_LIBV_VERIFIER_H_

#include <libv/libv.h>
#include <common/curl_util.h>
#include <common/measurement.h>
#include <common/utility.h>
#include <vector>

#define SERVICE_UPLOAD_NAME "/upload.php"
#define SERVICE_DOWNLOAD_NAME "/download.php"

#define VARIANT_PEPPER 0
#define VARIANT_HABANERO 1

class Verifier {
  protected:
    Venezia * v;
    Measurement measurement;

    int batch_size;
    int num_repetitions;
    int input_size;
    int optimize_answers;
    uint32_t num_bits_in_input;
    uint32_t num_bits_in_prime;
    char scratch_str[BUFLEN];
    char scratch_str2[BUFLEN];
    mpz_t prime;
    int expansion_factor;
    int crypto_in_use, png_in_use;
    mpz_t *c_values;

    // queries of different sizes.
    vector < uint32_t > commitment_query_sizes;
    vector < mpz_t * >f_commitment_ptrs;
    vector < mpz_t * >f_consistency_ptrs;

    vector < mpz_t * >con_coins_ptrs;
    vector < mpz_t * >temp_arr_ptrs;
    vector < mpz_t * >scalar_s_ptrs;
    vector < mpz_t * >scalar_a_ptrs;
    vector < mpz_t * >answers_ptrs;
    vector < uint32_t > L_list;
    vector < uint32_t > Q_list;
    vector < uint32_t > C_list;
    uint32_t num_lin_pcp_queries;

    // curl variables
    CurlUtil *curl;
    char prover_query_url[BUFLEN];
    char prover_upload_url[BUFLEN];
    char prover_download_url[BUFLEN];
    char download_url[BUFLEN];
    char full_file_name[BUFLEN];
    char full_url[BUFLEN];

    virtual void create_input() = 0;
    virtual void create_plain_queries() = 0;
    virtual void run_correction_and_circuit_tests(uint32_t beta) = 0;
    virtual void recv_outputs() = 0;
    void init_state();
    void run_tests();
    void init_server_variables(char *prover_url, const char *prover_name);
    void send_file(char *file_name);
    void recv_file(const char *file_name);
    void recv_com_answers(); 
    void invoke_prover(int prover_phase);
    void create_commitment_query();
    void load_consistency_query();
    void create_lin_queries(int f_num, int rho, int inp_size,
                            mpz_t * f_consistency, int *f_con_filled,
                            mpz_t * f_con_coins);

  public:
    Verifier(int batch, int reps, int ip_size, int optimize_answers,
             char *prover_host_url, const char *prover_name);
    ~Verifier(void);
    void begin_pepper();
    void begin_habanero();
};
#endif  // CODE_PEPPER_LIBV_VERIFIER_H_
