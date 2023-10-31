#ifndef PACKAGE
#define PACKAGE
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION
#include <bfd.h>
#undef PACKAGE_VERSION
#else
#include <bfd.h>
#endif
#undef PACKAGE
#else
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION
#include <bfd.h>
#undef PACKAGE_VERSION
#else
#include <bfd.h>
#endif
#endif
#define PACKAGE 1
#define PACKAGE_VERSION "fuckyoubinutils"

#include <stdint.h>
#include <stdio.h>

struct bfd;
uint64_t get_section_count(void *abfd) {
  return (uint64_t)bfd_count_sections(abfd);
}

uint64_t get_start_address(void *abfd) {
  return (uint64_t)bfd_get_start_address(abfd);
}

struct bfd_section *get_sections(bfd *abfd) { return abfd->sections; }
struct bfd_section *get_last_section(bfd *abfd) { return abfd->section_last; }

int iter_func(const bfd_target *target, void *none) {
  (void)none;
  printf("target->name: %s\n", target->name);
  return 0;
}

// int main(void) {
//	bfd_iterate_over_targets(iter_func, NULL);
//
//
//	return 0;
// }
