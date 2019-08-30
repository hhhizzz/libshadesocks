#include <gtest/gtest.h>
#include <glog/logging.h>
#include "ss_server.h"

int main(int argc, char** argv) {
  uv_loop_t* loop = (uv_loop_t*)malloc(sizeof(uv_loop_t));
  uv_loop_init(loop);

  printf("Now quitting.\n");
  uv_run(loop, UV_RUN_DEFAULT);

  uv_loop_close(loop);
  free(loop);
  return 0;
}