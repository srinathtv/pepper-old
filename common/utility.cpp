#include <common/utility.h>

// COMMON UTILITIES
void parse_args(int argc, char **argv, int *phase, int *batch_size, int
  *num_verifications, int *input_size, char *prover_url, int *variant,
  int *optimize_answers)
{
  if (argc < 9)
  {
    cout<<"Fewer arguments passed; aborting!"<<endl;
    cout<<"Input format [-p <1|2>] -b <num_of_batches> -r <num_verifier_repetitions> -i <input_size> [-s <prover_url>] [-v <0|1>] [-o <0|1>]"<<endl;
    exit(1);
  }
  
  if (prover_url != NULL)
    prover_url[0] = '\0';

  for (int i=1; i<argc; i++)
  {
    if (strcmp(argv[i], "-p") == 0 && phase != NULL)
      *phase = atoi (argv[i+1]);
    else if (strcmp(argv[i], "-b") == 0)
      *batch_size = atoi (argv[i+1]);
    else if (strcmp(argv[i], "-r") == 0)
      *num_verifications = atoi (argv[i+1]);
    else if (strcmp(argv[i], "-i") == 0)
      *input_size = atoi (argv[i+1]);
    else if (strcmp(argv[i], "-s") == 0 && prover_url != NULL)
    {
      strncpy(prover_url, argv[i+1], BUFLEN-1);
      prover_url[BUFLEN-1] = '\0';
    }
    else if (strcmp(argv[i], "-v") == 0 && variant != NULL)
      *variant = atoi (argv[i+1]);
    else if (strcmp(argv[i], "-o") == 0 && optimize_answers != NULL)
      *optimize_answers = atoi (argv[i+1]); 
  }
}

void parse_http_args(char *query_string, int *phase, int *batch_size,
  int *num_verifications, int *input_size, int *optimize_answers)
{
  if (query_string == NULL)
  {
    return;
  }

  char *ptr = strtok(query_string, "=&");
  
  int key_id = -1;
  while (ptr != NULL)
  {
    if (strstr(ptr, "phase") != NULL)
      key_id = 0;
    else if (strstr(ptr, "batch_size") != NULL)
      key_id = 1;
    else if (strstr(ptr, "reps") != NULL)
      key_id = 2;
    else if (strstr(ptr, "m") != NULL)
      key_id = 3;
    else if (strstr(ptr, "opt") != NULL)
      key_id = 4;
    else
    {
      int arg = 0;
      if (key_id != -1)
        arg = atoi(ptr);
      
      switch (key_id)
      {
        case 0: *phase = arg; break;
        case 1: *batch_size = arg; break;
        case 2: *num_verifications = arg; break;
        case 3: *input_size = arg; break;
        case 4: *optimize_answers = arg; break;
      }
      key_id = -1;
    }
    ptr = strtok(NULL, "=&");
  }
}

void create_file(FILE **fp, const char *vec_name, char *permission, const char *folder_name)
{
  char file_name[BUFLEN];
  
  if (folder_name == NULL)
    snprintf(file_name, BUFLEN-1, "computation_state/%s", vec_name);
  else
    snprintf(file_name, BUFLEN-1, "%s/%s", folder_name, vec_name);

  *fp = fopen(file_name, permission);
  if (*fp == NULL)
  {
    cout <<"Could not operate file "<<file_name<<" with permision "<<permission<<endl;
    exit(1);
  }
}

void convert_to_z(const int size, mpz_t *z, const mpq_t *q, const mpz_t prime)
{
  for (int i = 0; i < size; i++)
  {
    mpz_invert(z[i], mpq_denref(q[i]), prime);
    mpz_mul(z[i], z[i], mpq_numref(q[i]));
    mpz_mod(z[i], z[i], prime);
  }
}

void dump_vector(int size, mpz_t *q, const char *vec_name, const char *folder_name)
{
  FILE *fp;
  create_file(&fp, vec_name, (char *)"wb", folder_name);
    
  for (int i=0; i<size; i++)
    mpz_out_raw(fp, q[i]);

  fclose(fp);
}

void dump_vector(int size, mpq_t *q, const char *vec_name, const char *folder_name)
{
  FILE *fp;
  create_file(&fp, vec_name, (char *)"wb", folder_name);
  for (int i=0; i<size; i++)
  {
    mpz_out_raw(fp, mpq_numref(q[i]));
    mpz_out_raw(fp, mpq_denref(q[i]));
  }
  fclose(fp);
}

/*
 * Dump an entire array of vectors. Useful when there are multiple functions in
 * the prover.
 *
 * Vectors will be stored with the following name:
 *      f<num_func>_<suffix>
 * num_func is an integer in [0, n).
 */
template<class T> void
dump_array(size_t n, T array[], const char *suffix, const char *folder_name)
{
  char arry_name[BUFLEN];

  for (size_t i = 0; i < n; i++)
  {
    snprintf(arry_name, sizeof(arry_name), "f%d_%s", i, suffix);
    array[i].dump_file(arry_name, folder_name);
  }
}

void dump_scalar(mpz_t q, char *scalar_name, const char *folder_name)
{
  FILE *fp;
  create_file(&fp, scalar_name, (char *)"wb", folder_name);
  mpz_out_raw(fp, q);
  fclose(fp);
}

/*
 * Dump an entire array of scalars. Useful when there are multiple functions in
 * the prover.
 *
 * Vectors will be stored with the following name:
 *      f<num_func>_<suffix>
 * num_func is an integer in [0, n).
 */
void dump_scalar_array(int n, mpz_t *scalars, const char *suffix, char *folder_name)
{
  char vec_name[BUFLEN];

  for (int i = 0; i < n; i++)
  {
    snprintf(vec_name, sizeof(vec_name), "f%d_%s", i, suffix);
    dump_scalar(scalars[i], vec_name, folder_name);
  }
}

void load_vector(int size, mpz_t *q, const char *vec_name, const char *folder_name)
{
  FILE *fp;
  create_file(&fp, vec_name, (char *)"rb", folder_name);
  for (int i=0; i<size; i++)
    mpz_inp_raw(q[i], fp);
  fclose(fp);
}

void load_vector(int size, mpq_t *q, const char *vec_name, const char *folder_name)
{
  FILE *fp;
  create_file(&fp, vec_name, (char *)"rb", folder_name);
  for (int i=0; i<size; i++)
  {
    mpz_inp_raw(mpq_numref(q[i]), fp);
    mpz_inp_raw(mpq_denref(q[i]), fp);
  }
  fclose(fp);
}

/*
 * Load an entire array of objects. Useful when there are multiple functions in
 * the prover.
 *
 * Vectors are expected to be stored with the following name:
 *      f<num_func>_<suffix>
 * num_func is an integer in [0, n).
 */
template<class T> void
load_array(size_t n, T array[], const char *suffix, const char *folder_name)
{
  char arry_name[BUFLEN];

  for (uint32_t i = 0; i < n; i++)
  {
    snprintf(arry_name, sizeof(arry_name), "f%d_%s", i, suffix);
    array[i].load_file(arry_name, folder_name);
  }
}

void load_scalar(mpz_t q, char *scalar_name, char *folder_name)
{
  FILE *fp;
  create_file(&fp, scalar_name, (char *)"rb", folder_name);
  mpz_inp_raw(q, fp);
  fclose(fp);
}

/*
 * Load an entire array of scalars. Useful when there are multiple functions in
 * the prover.
 *
 * Vectors will be stored with the following name:
 *      f<num_func>_<suffix>
 * num_func is an integer in [0, n).
 */
void load_scalar_array(int n, mpz_t *scalars, const char *suffix, char *folder_name)
{
  char vec_name[BUFLEN];

  for (int i = 0; i < n; i++)
  {
    snprintf(vec_name, sizeof(vec_name), "f%d_%s", i, suffix);
    load_scalar(scalars[i], vec_name, folder_name);
  }
}

void load_txt_scalar(mpz_t q, char *scalar_name, char *folder_name)
{
  FILE *fp;
  create_file(&fp, scalar_name, (char *)"rb", folder_name);
  mpz_inp_str(q, fp, 10);
  fclose(fp);
}

void alloc_init_vec(mpz_t **arr, uint32_t size)
{
  *arr = new mpz_t[size];
  for (uint32_t i=0; i<size; i++)
    mpz_init2((*arr)[i], INIT_MPZ_BITS);
}

void alloc_init_vec(mpq_t **arr, uint32_t size)
{
  *arr = new mpq_t[size];
  for (uint32_t i=0; i<size; i++)
  {
    mpq_init((*arr)[i]);
    mpq_set_ui((*arr)[i], 0, 1);
  }
}

void alloc_init_vec_array(const uint32_t *sizes, mpz_t **array, const uint32_t n)
{
  for (uint32_t i = 0; i < n; i++)
    alloc_init_vec(&array[i], sizes[i]);
}

void alloc_init_vec_array(const uint32_t size, mpz_t **array, const uint32_t n)
{
  for (uint32_t i = 0; i < n; i++)
    alloc_init_vec(&array[i], size);
}

void alloc_init_scalar(mpz_t s)
{
  mpz_init2(s, INIT_MPZ_BITS);
}

void print_matrix(mpz_t *matrix, uint32_t num_rows, uint32_t num_cols, string name)
{
  cout << "\n" << name << " =" << endl;
  for (uint32_t i = 0; i < num_rows*num_cols; i++)
  {
    gmp_printf("%Zd ", matrix[i]);
    if (i % num_cols == num_cols - 1)
      gmp_printf("\n");
  }
  cout << endl;
}

void print_sq_matrix(mpz_t *matrix, uint32_t size, string name)
{
  print_matrix(matrix, size, size, name);
}

void* aligned_malloc(size_t size)
{
  void* ptr = malloc(size + PAGESIZE);

  if (ptr)
  {
    void* aligned = (void*)(((long)ptr + PAGESIZE) & ~(PAGESIZE - 1));
    ((void**)aligned)[-1] = ptr;
    return aligned;
  }
  else
    return NULL;
}
