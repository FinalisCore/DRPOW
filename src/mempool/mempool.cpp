#include "rpov2/mempool.h"

#include <algorithm>

#include "rpov2/tx_codec.h"

namespace rpov2 {

static std::string IdKey(const Bytes32& id)
{
    return std::string((const char*)id.v, 32);
}

bool Mempool::AddSpend(const SpendTx& tx, std::string* err)
{
    Bytes32 id;
    if (!ComputeSpendTxId(tx, &id))
    {
        if (err)
            *err = "spend_txid_failed";
        return false;
    }
    std::string k = IdKey(id);
    if (std::find(spend_ids_.begin(), spend_ids_.end(), k) != spend_ids_.end())
    {
        if (err)
            *err = "duplicate_spend";
        return false;
    }
    spend_ids_.push_back(k);
    spends_.push_back(tx);
    return true;
}

bool Mempool::AddMint(const MintTx& tx, std::string* err)
{
    Bytes32 id;
    if (!ComputeMintTxId(tx, &id))
    {
        if (err)
            *err = "mint_txid_failed";
        return false;
    }
    std::string k = IdKey(id);
    if (std::find(mint_ids_.begin(), mint_ids_.end(), k) != mint_ids_.end())
    {
        if (err)
            *err = "duplicate_mint";
        return false;
    }
    mint_ids_.push_back(k);
    mints_.push_back(tx);
    return true;
}

std::vector<SpendTx> Mempool::DrainSpends(size_t limit)
{
    if (limit == 0 || spends_.empty())
        return std::vector<SpendTx>();
    if (limit > spends_.size())
        limit = spends_.size();
    std::vector<SpendTx> out(spends_.begin(), spends_.begin() + (long)limit);
    spends_.erase(spends_.begin(), spends_.begin() + (long)limit);
    spend_ids_.erase(spend_ids_.begin(), spend_ids_.begin() + (long)limit);
    return out;
}

std::vector<MintTx> Mempool::DrainMints(size_t limit)
{
    if (limit == 0 || mints_.empty())
        return std::vector<MintTx>();
    if (limit > mints_.size())
        limit = mints_.size();
    std::vector<MintTx> out(mints_.begin(), mints_.begin() + (long)limit);
    mints_.erase(mints_.begin(), mints_.begin() + (long)limit);
    mint_ids_.erase(mint_ids_.begin(), mint_ids_.begin() + (long)limit);
    return out;
}

size_t Mempool::SpendCount() const
{
    return spends_.size();
}

size_t Mempool::MintCount() const
{
    return mints_.size();
}

}  // namespace rpov2
