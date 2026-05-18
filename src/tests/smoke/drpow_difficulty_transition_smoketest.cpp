#include <stdio.h>
#include <string.h>

#include "economics_policy.h"

using namespace drpow;

static Bytes32 U8Target(uint8_t v)
{
    Bytes32 b;
    memset(b.v, 0x00, 32);
    b.v[31] = v;
    return b;
}

static bool Eq(const Bytes32& a, const Bytes32& b)
{
    return memcmp(a.v, b.v, 32) == 0;
}

int main()
{
    const Bytes32 min_t = U8Target(1);
    const Bytes32 max_t = U8Target(255);
    Bytes32 out;

    // normal: observed == expected, unchanged
    if (!NextPowTargetDeterministic(U8Target(100), 10, 10, 2000000, 500000, min_t, max_t, &out) || !Eq(out, U8Target(100)))
    {
        printf("difficulty_vector_normal_failed\n");
        return 1;
    }
    // bursty: observed > expected => harder (lower target)
    if (!NextPowTargetDeterministic(U8Target(100), 20, 10, 2000000, 500000, min_t, max_t, &out) || !Eq(out, U8Target(50)))
    {
        printf("difficulty_vector_bursty_failed\n");
        return 2;
    }
    // stalled: observed < expected => easier (higher target), bounded by +2x
    if (!NextPowTargetDeterministic(U8Target(100), 1, 10, 2000000, 500000, min_t, max_t, &out) || !Eq(out, U8Target(200)))
    {
        printf("difficulty_vector_stalled_failed\n");
        return 3;
    }
    // boundary high clamp
    if (!NextPowTargetDeterministic(U8Target(250), 1, 10, 2000000, 500000, min_t, max_t, &out) || !Eq(out, U8Target(255)))
    {
        printf("difficulty_vector_boundary_high_failed\n");
        return 4;
    }
    // boundary low clamp
    if (!NextPowTargetDeterministic(U8Target(2), 100, 10, 2000000, 500000, min_t, max_t, &out) || !Eq(out, U8Target(1)))
    {
        printf("difficulty_vector_boundary_low_failed\n");
        return 5;
    }

    printf("ok difficulty_transition_vectors\n");
    return 0;
}
