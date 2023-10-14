package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/core/types"
)

type Policy struct {
	MaxAmountWei *big.Int   `json:"max_amount_wei"`
	Whitelist    []string   `json:"whitelist"`
}

func loadPrivateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(hexKey, "0x"))
}

func loadPolicy(file string) (*Policy, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func checkPolicy(policy *Policy, to common.Address, amount *big.Int) error {
	// Check whitelist
	allowed := false
	for _, addr := range policy.Whitelist {
		if strings.EqualFold(addr, to.Hex()) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("recipient not in whitelist")
	}
	// Check amount
	if amount.Cmp(policy.MaxAmountWei) > 0 {
		return errors.New("amount exceeds max policy limit")
	}
	return nil
}

func main() {
	var privKeyHex string
	var toAddr string
	var amountWeiStr string
	var nonce uint64
	var chainID int64
	var policyFile string

	flag.StringVar(&privKeyHex, "key", "", "Private key in hex")
	flag.StringVar(&toAddr, "to", "", "Recipient address")
	flag.StringVar(&amountWeiStr, "amount", "0", "Amount in wei")
	flag.Uint64Var(&nonce, "nonce", 0, "Account nonce")
	flag.Int64Var(&chainID, "chain", 1, "Chain ID (default Ethereum mainnet)")
	flag.StringVar(&policyFile, "policy", "policy.json", "Path to policy JSON file")
	flag.Parse()

	if privKeyHex == "" || toAddr == "" {
		log.Fatal("key and to are required")
	}

	privateKey, err := loadPrivateKey(privKeyHex)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	policy, err := loadPolicy(policyFile)
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	amountWei, ok := new(big.Int).SetString(amountWeiStr, 10)
	if !ok {
		log.Fatal("invalid amount")
	}

	to := common.HexToAddress(toAddr)

	// Policy checks
	if err := checkPolicy(policy, to, amountWei); err != nil {
		log.Fatalf("policy check failed: %v", err)
	}

	// Create transaction
	tx := types.NewTransaction(nonce, to, amountWei, 21000, big.NewInt(1_000_000_000), nil)

	// Sign transaction
	signer := types.LatestSignerForChainID(big.NewInt(chainID))
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		log.Fatalf("failed to sign tx: %v", err)
	}

	// Serialize
	rawTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		log.Fatalf("failed to serialize tx: %v", err)
	}

	fmt.Println("RawTxHex:", hex.EncodeToString(rawTxBytes))
}
