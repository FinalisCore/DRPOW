#ifndef DRPOW_MEMPOOL_MEMPOOL_H
#define DRPOW_MEMPOOL_MEMPOOL_H

#include <stddef.h>
#include <string>
#include <vector>

#include "drpow/tx_types.h"

namespace drpow {

class Mempool {
public:
    bool AddSpend(const SpendTx& tx, std::string* err);
    bool AddMint(const MintTx& tx, std::string* err);

    std::vector<SpendTx> DrainSpends(size_t limit);
    std::vector<MintTx> DrainMints(size_t limit);

    size_t SpendCount() const;
    size_t MintCount() const;

private:
    std::vector<SpendTx> spends_;
    std::vector<MintTx> mints_;
    std::vector<std::string> spend_ids_;
    std::vector<std::string> mint_ids_;
};

}  // namespace drpow

#endif
