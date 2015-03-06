#ifndef CURVE25519_H
#define CURVE25519_H

#include "config.h"

static const unsigned char curve25519_basepoint[32] = {9};

int curve25519 (unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

#endif
