#include <common/measurement.h>

Measurement::Measurement()
{
  ru_time_sofar = 0;
  papi_time_sofar = 0;
}

void Measurement::begin_with_init()
{
  ru_time_sofar = 0;
  papi_time_sofar = 0;
  begin_with_history();
}

void Measurement::begin_with_history()
{
  getrusage(RUSAGE_SELF, &ru_start);
  papi_start = PAPI_get_real_usec();
}

void Measurement::end()
{
  papi_end = PAPI_get_real_usec(); 
  getrusage(RUSAGE_SELF, &ru_end);
  
  papi_time_sofar += (papi_end - papi_start);
  
  struct timeval start_time = ru_start.ru_utime;
  struct timeval end_time = ru_end.ru_utime;

  double ts = start_time.tv_sec*1000000 + (start_time.tv_usec);
  double te = end_time.tv_sec*1000000  + (end_time.tv_usec);
  ru_time_sofar += (te-ts);

  // add system time
  start_time = ru_start.ru_stime;
  end_time = ru_end.ru_stime;

  ts = start_time.tv_sec*1000000 + (start_time.tv_usec);
  te = end_time.tv_sec*1000000  + (end_time.tv_usec);
  ru_time_sofar += (te-ts);

}

double Measurement::get_ru_elapsed_time()
{
  return ru_time_sofar;
}

double Measurement::get_papi_elapsed_time()
{
  return papi_time_sofar;
}
