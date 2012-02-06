#ifndef CODE_PEPPER_COMMON_MEASUREMENT_H_  
#define CODE_PEPPER_COMMON_MEASUREMENT_H_  

#include <sys/time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <papi.h>

#define INNER_LOOP_TINY 1
#define INNER_LOOP_SMALL 5 
#define INNER_LOOP_MEDIUM 100
#define INNER_LOOP_LARGE 1000
#define INNER_LOOP_XLARGE 10000

class Measurement {
  private:
    struct rusage ru_start, ru_end;
    long long papi_start, papi_end;
    double ru_time_sofar, papi_time_sofar;

  public:
    Measurement();
    void begin_with_init();
    void begin_with_history();
    void end();
    double get_ru_elapsed_time();
    double get_papi_elapsed_time();
};
#endif  // CODE_PEPPER_COMMON_MEASUREMENT_H_
