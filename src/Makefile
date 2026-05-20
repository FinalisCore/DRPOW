CXX ?= g++
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS ?= -lcrypto
USE_LIBOQS ?= auto
DRPOW_BUILD_ID ?= $(shell git -C $(CURDIR) rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
CXXFLAGS += -I. -Iinclude -Iinclude/drpow -Iprotocol/tx -Icrypto -Iconsensus -Inetwork -Istorage -Iproof -Icli -Inode
CXXFLAGS += -DDRPOW_BUILD_ID=\"$(DRPOW_BUILD_ID)\"
BUILD_DIR ?= build

LOCAL_LIBOQS_PC_DIR := $(CURDIR)/liboqs/install/lib/pkgconfig
PKG_CONFIG_PATH_EFFECTIVE := $(LOCAL_LIBOQS_PC_DIR):$(PKG_CONFIG_PATH)

ifeq ($(USE_LIBOQS),auto)
HAVE_LIBOQS := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH_EFFECTIVE)" pkg-config --exists liboqs 2>/dev/null && echo 1 || echo 0)
USE_LIBOQS := $(HAVE_LIBOQS)
endif

ifeq ($(USE_LIBOQS),1)
LIBOQS_CFLAGS := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH_EFFECTIVE)" pkg-config --cflags liboqs 2>/dev/null)
LIBOQS_LIBS := $(shell PKG_CONFIG_PATH="$(PKG_CONFIG_PATH_EFFECTIVE)" pkg-config --libs liboqs 2>/dev/null)
ifeq ($(strip $(LIBOQS_CFLAGS)$(LIBOQS_LIBS)),)
$(error USE_LIBOQS=1 but liboqs was not found by pkg-config. Set PKG_CONFIG_PATH (for example: /tmp/liboqs-install/lib/pkgconfig) or install liboqs development files)
endif
CXXFLAGS += $(LIBOQS_CFLAGS) -DUSE_LIBOQS=1
LDLIBS += $(LIBOQS_LIBS)
endif

DRPOW_COMMON_SRCS = \
	crypto/crypto_backend.cpp \
	crypto/state_commitment.cpp \
	consensus/economics_policy.cpp \
	consensus/drpow_params.cpp \
	network/p2p_wire.cpp \
	network/node_config.cpp \
	network/p2p_reactor.cpp \
	protocol/tx/tx_codec.cpp \
	consensus/finality_qc.cpp \
	proof/proof_verifier.cpp \
	consensus/consensus_round.cpp \
	storage/registry_state_store.cpp
DRPOW_WALLET_SRCS = \
	address/address.cpp \
	wallet/wallet.cpp \
	mempool/mempool.cpp

DRPOW_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_smoketest.cpp
DRPOW_REPLAY_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_replay_smoketest.cpp
DRPOW_PROOF_POLICY_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_proof_policy_smoketest.cpp
DRPOW_PROOF_BUDGET_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_proof_budget_smoketest.cpp
DRPOW_PROOF_MIGRATION_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_proof_migration_smoketest.cpp
DRPOW_POW_ELIGIBILITY_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_pow_eligibility_smoketest.cpp
DRPOW_DIFFICULTY_TRANSITION_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_difficulty_transition_smoketest.cpp
DRPOW_QC_THRESHOLD_SMOKETEST_SRCS = $(DRPOW_COMMON_SRCS) tests/smoke/drpow_qc_threshold_smoketest.cpp

.PHONY: all clean test

all: drpow_smoketest drpow_replay_smoketest drpow_proof_policy_smoketest drpow_proof_budget_smoketest drpow_proof_migration_smoketest drpow_pow_eligibility_smoketest drpow_difficulty_transition_smoketest drpow_qc_threshold_smoketest drpow_node drpow_cli

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/drpow_smoketest: $(DRPOW_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_replay_smoketest: $(DRPOW_REPLAY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_REPLAY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_proof_policy_smoketest: $(DRPOW_PROOF_POLICY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_PROOF_POLICY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_proof_budget_smoketest: $(DRPOW_PROOF_BUDGET_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_PROOF_BUDGET_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_proof_migration_smoketest: $(DRPOW_PROOF_MIGRATION_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_PROOF_MIGRATION_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_pow_eligibility_smoketest: $(DRPOW_POW_ELIGIBILITY_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_POW_ELIGIBILITY_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_difficulty_transition_smoketest: $(DRPOW_DIFFICULTY_TRANSITION_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_DIFFICULTY_TRANSITION_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_qc_threshold_smoketest: $(DRPOW_QC_THRESHOLD_SMOKETEST_SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_QC_THRESHOLD_SMOKETEST_SRCS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_node: $(DRPOW_COMMON_SRCS) mempool/mempool.cpp node/drpow_node_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_COMMON_SRCS) mempool/mempool.cpp node/drpow_node_main.cpp $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/drpow_cli: $(DRPOW_COMMON_SRCS) $(DRPOW_WALLET_SRCS) cli/drpow_cli_main.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(DRPOW_COMMON_SRCS) $(DRPOW_WALLET_SRCS) cli/drpow_cli_main.cpp $(LDFLAGS) $(LDLIBS)

drpow_smoketest: $(BUILD_DIR)/drpow_smoketest
drpow_replay_smoketest: $(BUILD_DIR)/drpow_replay_smoketest
drpow_proof_policy_smoketest: $(BUILD_DIR)/drpow_proof_policy_smoketest
drpow_proof_budget_smoketest: $(BUILD_DIR)/drpow_proof_budget_smoketest
drpow_proof_migration_smoketest: $(BUILD_DIR)/drpow_proof_migration_smoketest
drpow_pow_eligibility_smoketest: $(BUILD_DIR)/drpow_pow_eligibility_smoketest
drpow_difficulty_transition_smoketest: $(BUILD_DIR)/drpow_difficulty_transition_smoketest
drpow_qc_threshold_smoketest: $(BUILD_DIR)/drpow_qc_threshold_smoketest
drpow_node: $(BUILD_DIR)/drpow_node
drpow_cli: $(BUILD_DIR)/drpow_cli

test: all
	./$(BUILD_DIR)/drpow_smoketest
	./$(BUILD_DIR)/drpow_replay_smoketest
	./$(BUILD_DIR)/drpow_proof_policy_smoketest
	./$(BUILD_DIR)/drpow_proof_budget_smoketest
	./$(BUILD_DIR)/drpow_proof_migration_smoketest
	./$(BUILD_DIR)/drpow_pow_eligibility_smoketest
	./$(BUILD_DIR)/drpow_difficulty_transition_smoketest
	./$(BUILD_DIR)/drpow_qc_threshold_smoketest

clean:
	rm -rf $(BUILD_DIR)
