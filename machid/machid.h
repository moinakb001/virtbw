#include <stdint.h>

int machid_start(const uint8_t *descriptor, int descriptor_length);
int machid_send(const uint8_t *report, int length);
