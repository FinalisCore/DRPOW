#include "state_commitment.h"

#include <cstddef>
#include <vector>

#include "rpov2/tx_codec.h"

namespace rpov2 {

namespace {

static bool HashTagged(const char* tag, const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, Bytes32* out)
{
    if (!tag || !out)
        return false;
    std::vector<uint8_t> m;
    while (*tag)
        m.push_back((uint8_t)*tag++);
    if (a && a_len > 0)
        m.insert(m.end(), a, a + a_len);
    if (b && b_len > 0)
        m.insert(m.end(), b, b + b_len);
    return Sha256(m, out);
}

}  // namespace

bool ComputeStateRootV1(const std::vector< std::vector<uint8_t> >& entries_256, Bytes32* out_root)
{
    if (!out_root)
        return false;

    if (entries_256.empty())
    {
        return HashTagged("RPOV2:empty:v1", NULL, 0, NULL, 0, out_root);
    }

    std::vector<Bytes32> layer;
    layer.reserve(entries_256.size());

    for (size_t i = 0; i < entries_256.size(); ++i)
    {
        if (entries_256[i].empty())
            return false;
        Bytes32 h;
        if (!HashTagged("RPOV2:leaf:v1", &entries_256[i][0], entries_256[i].size(), NULL, 0, &h))
            return false;
        layer.push_back(h);
    }

    while (layer.size() > 1)
    {
        std::vector<Bytes32> next;
        next.reserve((layer.size() + 1) / 2);

        for (size_t i = 0; i < layer.size(); i += 2)
        {
            const Bytes32& left = layer[i];
            const Bytes32& right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
            Bytes32 parent;
            if (!HashTagged("RPOV2:node:v1", left.v, 32, right.v, 32, &parent))
                return false;
            next.push_back(parent);
        }

        layer.swap(next);
    }

    *out_root = layer[0];
    return true;
}

}  
