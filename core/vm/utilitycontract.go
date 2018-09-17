package vm

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type BalanceOf struct {
	Owner common.Address
}

type Token struct {
	Symbol   string
	Address  common.Address
	Decimals int
	Name     string
}

var (
	tokens  []Token
	utility = `[ { "constant": true, "inputs": [{ "name": "Owner", "type": "address" }], "name": "getAllBalance", "outputs": [{ "name": "balance", "type": "uint256" }], "payable": false, "stateMutability": "view", "type": "function" }]`

	utilityAbi, _ = abi.JSON(strings.NewReader(utility))
	getAllBalance [4]byte
	tokenConfig   = map[int64]string{}
)

type utilityContract struct{}

func (c *utilityContract) RequiredGas(input []byte) uint64 {
	return 1
}

func (c *utilityContract) Run(input []byte, evm *EVM) ([]byte, error) {
	var (
		tokenBalanceOf BalanceOf
		method         [4]byte
		// TODO: read this token list from json
		// https://github.com/MyEtherWallet/utility-contracts/blob/master/tokens/tokens-eth.json
		tokensBalance = map[common.Address]*big.Int{}

		token       = `[ { "inputs": [ { "name": "addr", "type": "address" } ], "payable": false, "stateMutability": "nonpayable", "type": "constructor" }, { "constant": false, "inputs": [ { "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "transfer", "outputs": [ { "name": "success", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [ { "name": "Owner", "type": "address" } ], "name": "balanceOf", "outputs": [ { "name": "balance", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" } ]`
		tokenabi, _ = abi.JSON(strings.NewReader(token))
	)

	if len(input) < 4 {
		return nil, nil
	}
	copy(method[:], input[:4])
	copy(getAllBalance[:], utilityAbi.Methods["getAllBalance"].Id())

	switch method {
	case getAllBalance:
		{
			utilityAbi.UnpackInput(&tokenBalanceOf, "getAllBalance", input[4:])
			encodedData, err := tokenabi.Pack("balanceOf", tokenBalanceOf.Owner)
			if err != nil {
				return nil, err
			}
			if len(tokens) == 0 {
				tokens, _ = initTokenList(evm.ChainConfig().ChainID.Int64())
			}
			for _, token := range tokens {
				ret, _, err := evm.StaticCall(AccountRef(common.BytesToAddress([]byte{9})), token.Address, encodedData, 1)
				if err != nil {
					tokensBalance[token.Address] = big.NewInt(0)
				}
				tokensBalance[token.Address] = new(big.Int).SetBytes(ret)
			}
			return json.Marshal(tokensBalance)
		}
	}
	return []byte("0"), nil
}

func init() {
	// map networkID and tokens
	// TODO add more networks / use separate repo for all  networks token lists
	tokenConfig[1] = "https://raw.githubusercontent.com/MyEtherWallet/utility-contracts/master/tokens/tokens-eth.json"
	tokenConfig[1234] = "https://gist.githubusercontent.com/niktrix/5f6ced49c2c782b73aa82c0ba19702cd/raw/b558066a979c57d58e11729212a4d10da1a91ab7/tokens"
}

func initTokenList(chainID int64) (tokens []Token, err error) {
	var (
		contents     []byte
		response     *http.Response
		url          string
		tokenSupport bool
	)
	url, tokenSupport = tokenConfig[chainID]
	if !tokenSupport {
		err = errors.New("Token Balance is not supported in this Chain")
		return
	}
	response, err = http.Get(url)
	defer response.Body.Close()
	contents, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	json.Unmarshal(contents, &tokens)
	return

}
