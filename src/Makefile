CXX ?= g++
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS ?= -lcrypto
USE_LIBOQS ?= 0
CXXFLAGS += -I. -Iinclude -Iinclude/rpov2 -Iprotocol/tx -Icrypto -Iconsensus -Inetwork -Istorage -Iproof -Icli -Inode
BUILD_DIR ?= build

ifeq ($(USE_LIBOQS),1)
LIBOQS_CFLAGS := $(shell pkg-config --cflags liboqs 2>/dev/null)
LIBOQS_LIBS := $(shell pkg-config --libs liboqs 2>/dev/null)
ifeq ($(strip $(LIBOQS_CFLAGS)$(LIBOQS_LIBS)),)
$(error USE_LIBOQS=1 but liboqs was not found by pkg-config. Set PKG_CONFIG_PATH (for example: /tmp/liboqs-install/lib/pkgconfig) or install liboqs development files)
endif
CXXFLAGS += $(LIBOQS_CFLAGS) -DUSE_LIBOQS=1
LDLIBS += $(LIBOQS_LIBS)
endif

RPOV2_COMMON_SRCS = \
	crypto/crypto_backend.cpp \
	crypto/state_commitment.cpp \
	consensus/economics_policy.cpp \
	network/p2p_wire.cpp \
	network/node_config.cpp \
	network/p2p_reactor.cpp \
	protocol/tx/tx_codec.cpp \
	consensus/finality_qc.cpp \
	proof/proof_verifier.cpp \
	consensus/validator_lottery.cpp \
	consensus/static_validator_set.cpp \
	consensus/pow_lottery_validator_set.cpp \
	consensus/consensus_round.cpp \
	storage/registry_state_store.cpp
RPOV2_WALLET_SRCS = \
	address/address.cpp \
	wallet/wallet.cpp \
	mempool/mempool.cpp

RPOV2_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_smoketest.cpp
RPOV2_LOTTERY_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_lottery_smoketest.cpp
RPOV2_REPLAY_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_replay_smoketest.cpp
RPOV2_PROOF_POLICY_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_proof_policy_smoketest.cpp
RPOV2_PROOF_BUDGET_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_proof_budget_smoketest.cpp
RPOV2_PROOF_MIGRATION_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_proof_migration_smoketest.cpp
RPOV2_POW_ELIGIBILITY_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_pow_eligibility_smoketest.cpp
RPOV2_POW_EPOCH_TRANSITION_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_pow_epoch_transition_smoketest.cpp
RPOV2_DIFFICULTY_TRANSITION_SMOKETEST_SRCS = $(RPOV2_COMMON_SRCS) tests/smoke/rpov2_difficulty_transition_smoketest.cpp

.PHONY: all clean test

all: rpov2_smoketest rpov2_lottery_smoketest rpov2_replay_smoketest rpov2_proof_policy_smoketest rpov2_proof_budget_smoketest rpov2_proof_migration_smoketest rpov2_pow_eligibility_smoketest rpov2_pow_epoch_transition_smoketest rpov2_difficulty_transition_smoketest rpov2_node rpov2_cli

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/rpov2_smoketest: $(RPOV2_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_lottery_smoketest: $(RPOV2_LOTTERY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_LOTTERY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_replay_smoketest: $(RPOV2_REPLAY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_REPLAY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_proof_policy_smoketest: $(RPOV2_PROOF_POLICY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_PROOF_POLICY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_proof_budget_smoketest: $(RPOV2_PROOF_BUDGET_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_PROOF_BUDGET_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_proof_migration_smoketest: $(RPOV2_PROOF_MIGRATION_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_PROOF_MIGRATION_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_pow_eligibility_smoketest: $(RPOV2_POW_ELIGIBILITY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_POW_ELIGIBILITY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_pow_epoch_transition_smoketest: $(RPOV2_POW_EPOCH_TRANSITION_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_POW_EPOCH_TRANSITION_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_difficulty_transition_smoketest: $(RPOV2_DIFFICULTY_TRANSITION_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_DIFFICULTY_TRANSITION_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_node: $(RPOV2_COMMON_SRCS) mempool/mempool.cpp node/rpov2_node_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_COMMON_SRCS) mempool/mempool.cpp node/rpov2_node_main.cpp $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/rpov2_cli: $(RPOV2_COMMON_SRCS) $(RPOV2_WALLET_SRCS) cli/rpov2_cli_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RPOV2_COMMON_SRCS) $(RPOV2_WALLET_SRCS) cli/rpov2_cli_main.cpp $(LDFLAGS) $(LDLIBS)

rpov2_smoketest: $(BUILD_DIR)/rpov2_smoketest
rpov2_lottery_smoketest: $(BUILD_DIR)/rpov2_lottery_smoketest
rpov2_replay_smoketest: $(BUILD_DIR)/rpov2_replay_smoketest
rpov2_proof_policy_smoketest: $(BUILD_DIR)/rpov2_proof_policy_smoketest
rpov2_proof_budget_smoketest: $(BUILD_DIR)/rpov2_proof_budget_smoketest
rpov2_proof_migration_smoketest: $(BUILD_DIR)/rpov2_proof_migration_smoketest
rpov2_pow_eligibility_smoketest: $(BUILD_DIR)/rpov2_pow_eligibility_smoketest
rpov2_pow_epoch_transition_smoketest: $(BUILD_DIR)/rpov2_pow_epoch_transition_smoketest
rpov2_difficulty_transition_smoketest: $(BUILD_DIR)/rpov2_difficulty_transition_smoketest
rpov2_node: $(BUILD_DIR)/rpov2_node
rpov2_cli: $(BUILD_DIR)/rpov2_cli

test: all
	./$(BUILD_DIR)/rpov2_smoketest
	./$(BUILD_DIR)/rpov2_lottery_smoketest
	./$(BUILD_DIR)/rpov2_replay_smoketest
	./$(BUILD_DIR)/rpov2_proof_policy_smoketest
	./$(BUILD_DIR)/rpov2_proof_budget_smoketest
	./$(BUILD_DIR)/rpov2_proof_migration_smoketest
	./$(BUILD_DIR)/rpov2_pow_eligibility_smoketest
	./$(BUILD_DIR)/rpov2_pow_epoch_transition_smoketest
	./$(BUILD_DIR)/rpov2_difficulty_transition_smoketest

clean:
	rm -rf $(BUILD_DIR)
