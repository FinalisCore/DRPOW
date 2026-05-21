#ifndef COIN_P2P_WIRE_H
#define COIN_P2P_WIRE_H

#include <cstddef>
#include <stdint.h>
#include <string>
#include <vector>

#include "consensus_round.h"
#include "finality_qc.h"
#include "state_store.h"
#include "drpow/tx_types.h"

namespace drpow {

enum WireMsgType {
    WIRE_MSG_HELLO = 0,
    WIRE_MSG_HELLO_CHALLENGE = 10,
    WIRE_MSG_HELLO_AUTH = 11,
    WIRE_MSG_TIMEOUT_VOTE = 12,
    WIRE_MSG_TX = 1,
    WIRE_MSG_PROPOSE = 2,
    WIRE_MSG_VOTE = 3,
    WIRE_MSG_COMMIT = 4,
    WIRE_MSG_LOTTERY_SHARE = 5,
    WIRE_MSG_SYNC_STATUS = 6,
    WIRE_MSG_SYNC_REQUEST = 7,
    WIRE_MSG_SYNC_RESPONSE = 8,
    WIRE_MSG_PEER_LIST = 9
};

struct WireEnvelope {
    uint32_t magic;
    uint16_t version;
    uint16_t msg_type;
    uint32_t payload_len;
    uint64_t unix_ms;
    Bytes32 payload_hash;
    std::vector<uint8_t> payload;
};

struct TimeoutVote {
    uint64_t round = 0;
    Bytes32 validator_id = Bytes32();
    Bytes32 lock_batch_hash = Bytes32();
    std::vector<uint8_t> signature;
};

uint32_t WireMagicMainnet();
bool WireSetMagic(uint32_t magic);
size_t WireMaxPayloadBytes();
bool SerializeWireEnvelope(const WireEnvelope& env, std::vector<uint8_t>* out);
bool ParseWireEnvelope(const std::vector<uint8_t>& in, WireEnvelope* out);
bool SerializeRoundBatchPayload(const RoundBatch& batch, std::vector<uint8_t>* out);
bool ParseRoundBatchPayload(const std::vector<uint8_t>& in, RoundBatch* out);
bool SerializeVotePayload(const Vote& vote, std::vector<uint8_t>* out);
bool ParseVotePayload(const std::vector<uint8_t>& in, Vote* out);
bool SerializeTimeoutVotePayload(const TimeoutVote& vote, std::vector<uint8_t>* out);
bool ParseTimeoutVotePayload(const std::vector<uint8_t>& in, TimeoutVote* out);
bool SerializeCommitPayload(const RoundBatch& batch, const QuorumCertificate& qc, std::vector<uint8_t>* out);
bool ParseCommitPayload(const std::vector<uint8_t>& in, RoundBatch* batch, QuorumCertificate* qc);
bool SerializeSyncStatusPayload(uint64_t last_committed_round, const Bytes32& state_root, std::vector<uint8_t>* out);
bool ParseSyncStatusPayload(const std::vector<uint8_t>& in, uint64_t* last_committed_round, Bytes32* state_root);
bool SerializeSyncRequestPayload(uint64_t from_round, uint32_t max_records, std::vector<uint8_t>* out);
bool ParseSyncRequestPayload(const std::vector<uint8_t>& in, uint64_t* from_round, uint32_t* max_records);
bool SerializeSyncResponsePayload(uint64_t from_round, const std::vector< std::vector<uint8_t> >& commit_payloads, std::vector<uint8_t>* out);
bool ParseSyncResponsePayload(const std::vector<uint8_t>& in, uint64_t* from_round, std::vector< std::vector<uint8_t> >* commit_payloads);
bool SerializePeerListPayload(uint64_t advertised_round,
                              const Bytes32& advertiser_id,
                              const std::vector<std::string>& peers,
                              const std::vector<uint8_t>& signature,
                              std::vector<uint8_t>* out);
bool ParsePeerListPayload(const std::vector<uint8_t>& in,
                          uint64_t* advertised_round,
                          Bytes32* advertiser_id,
                          std::vector<std::string>* peers,
                          std::vector<uint8_t>* signature);
bool SerializeSpendTxSubmitPayload(const SpendTx& tx, std::vector<uint8_t>* out);
bool ParseSpendTxSubmitPayload(const std::vector<uint8_t>& in, SpendTx* out);
bool SerializeHelloChallengePayload(const Bytes32& challenge, std::vector<uint8_t>* out);
bool ParseHelloChallengePayload(const std::vector<uint8_t>& in, Bytes32* challenge);
bool SerializeHelloAuthPayload(const Bytes32& node_id,
                               const Bytes32& challenge,
                               const char* params_version,
                               const Bytes32& params_hash,
                               const char* build_id,
                               const std::vector<uint8_t>& signature,
                               std::vector<uint8_t>* out);
bool ParseHelloAuthPayload(const std::vector<uint8_t>& in,
                           Bytes32* node_id,
                           Bytes32* challenge,
                           std::string* params_version,
                           Bytes32* params_hash,
                           std::string* build_id,
                           std::vector<uint8_t>* signature);

}  

#endif
