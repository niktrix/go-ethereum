// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rdb

import (
	r "gopkg.in/gorethink/gorethink.v3"
	"github.com/ethereum/go-ethereum/core/types"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"math/big"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/common"
)

type Rconn struct {
	url string
	session *r.Session
}

type BlockIn struct {
	Block *types.Block
	State *state.StateDB
	PrevTd *big.Int
	Receipts types.Receipts
	Signer types.Signer
	IsUncle bool
}

func (rdb *Rconn) SetURL(url string) {
	rdb.url = url
}
func (rdb *Rconn) Connect() error {
	session, err := r.Connect(r.ConnectOpts{
		Address: rdb.url,
	})
	if err == nil{
		rdb.session = session
	}
	return  err
}

func (rdb *Rconn) InsertBlock(blockIn *BlockIn) {
	formatTx := func(tx *types.Transaction, index int) (interface{}, error) {
		receipt := blockIn.Receipts[index]
		head := blockIn.Block.Header()
		if receipt == nil {
			log.Debug("Receipt not found for transaction", "hash", tx.Hash())
			return nil, nil
		}
		signer := blockIn.Signer
		from, _ := types.Sender(signer, tx)
		_v, _r, _s := tx.RawSignatureValues()
		var fromBalance = blockIn.State.GetBalance(from)
		var toBalance = big.NewInt(0)
		if tx.To() != nil {
			toBalance = blockIn.State.GetBalance(*tx.To())
		}
		formatTopics := func(topics []common.Hash) ([]string){
			arrTopics:= make([]string, len(topics))
			for i, topic:= range topics {
				arrTopics[i] = topic.String()
			}
			return  arrTopics
		}
		formatLogs := func(logs []*types.Log) (interface{}){
			dLogs := make([]interface{}, len(logs))
			for i, log := range logs {
				logFields := map[string]interface{}{
					"address": log.Address.String(),
					"topics": formatTopics(log.Topics),
					"data": hexutil.Bytes(log.Data).String(),
					"blockNumber": hexutil.Uint64(log.BlockNumber).String(),
					"txHash": log.TxHash.String(),
					"txIndex": hexutil.Uint64(log.Index).String(),
					"blockHash": log.BlockHash.String(),
					"index": hexutil.Uint64(log.Index).String(),
					"removed": log.Removed,
				}
				dLogs[i] = logFields
			}
			return dLogs
		}
		rfields := map[string]interface{}{
			"root":              blockIn.Block.Header().ReceiptHash.String(),
			"blockHash":         blockIn.Block.Hash().String(),
			"blockNumber":       (*hexutil.Big)(head.Number).String(),
			"transactionIndex":  hexutil.Uint64(index).String(),
			"from":              from.String(),
			"fromBalance":       (*hexutil.Big)(fromBalance).String(),
			"to":                func() string { if tx.To() == nil { return string("") } else { return tx.To().String() } }(),
			"toBalance":         (*hexutil.Big)(toBalance).String(),
			"gasUsed":           (*hexutil.Big)(receipt.GasUsed).String(),
			"cumulativeGasUsed": (*hexutil.Big)(receipt.CumulativeGasUsed).String(),
			"contractAddress":   nil,
			"logs":              formatLogs(receipt.Logs),
			"logsBloom":         hexutil.Bytes(receipt.Bloom.Bytes()).String(),
			"gas":               (*hexutil.Big)(tx.Gas()).String(),
			"gasPrice":          (*hexutil.Big)(tx.GasPrice()).String(),
			"hash":              tx.Hash().String(),
			"input":             hexutil.Bytes(tx.Data()).String(),
			"nonce":             hexutil.Uint64(tx.Nonce()).String(),
			"value":             (*hexutil.Big)(tx.Value()).String(),
			"v":                 (*hexutil.Big)(_v).String(),
			"r":                 (*hexutil.Big)(_r).String(),
			"s":                 (*hexutil.Big)(_s).String(),
			"status":			 hexutil.Uint(receipt.Status),
		}
		if len(receipt.Logs) == 0 {
			rfields["logs"] = nil
			rfields["logsBloom"] = nil
		}
		// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
		if receipt.ContractAddress != (common.Address{}) {
			rfields["contractAddress"] = receipt.ContractAddress
		}
		return rfields, nil
	}
	processTxs := func(txs types.Transactions) ([]interface{}) {
		pTxs := make([]interface{}, len(txs))
		for i, tx:= range txs {
			pTxs[i], _ = formatTx(tx, i)
		}
		return pTxs
	}
	formatBlock := func(block *types.Block) (map[string]interface{}, error) {
		head := block.Header() // copies the header once
		minerBalance := blockIn.State.GetBalance(head.Coinbase)
		bfields := map[string]interface{}{
			"id": 				head.Hash().String(),
			"number":           hexutil.Uint64(head.Number.Uint64()).String(),
			"intNumber":        hexutil.Uint64(head.Number.Uint64()),
			"hash":             head.Hash().String(),
			"parentHash":       head.ParentHash.String(),
			"nonce":            hexutil.Uint64(head.Nonce.Uint64()).String(),
			"mixHash":          head.MixDigest.String(),
			"sha3Uncles":       head.UncleHash.String(),
			"logsBloom":        hexutil.Bytes(head.Bloom.Bytes()).String(),
			"stateRoot":        head.Root.String(),
			"miner":            head.Coinbase.String(),
			"minerBalance":     (*hexutil.Big)(minerBalance).String(),
			"difficulty":       (*hexutil.Big)(head.Difficulty).String(),
			"totalDifficulty":  func() string {
									if blockIn.PrevTd==nil {
										return string("")
									}
									return (*hexutil.Big)(new(big.Int).Add(block.Difficulty(), blockIn.PrevTd)).String()
								}(),
			"extraData":        hexutil.Bytes(head.Extra).String(),
			"size":             hexutil.Uint64(uint64(block.Size().Int64())).String(),
			"gasLimit":         (*hexutil.Big)(head.GasLimit).String(),
			"gasUsed":          (*hexutil.Big)(head.GasUsed).String(),
			"timestamp":        (*hexutil.Big)(head.Time).String(),
			"transactionsRoot": head.TxHash.String(),
			"receiptsRoot":     head.ReceiptHash.String(),
			"transactions": 	processTxs(block.Transactions()),
			"uncles":			func() []string {
									uncles:= make([]string, len(block.Uncles()))
									for i, uncle:= range block.Uncles() {
										uncles[i] = uncle.Hash().String()
										rdb.InsertBlock(&BlockIn{
											Block:types.NewBlockWithHeader(uncle),
											State:blockIn.State,
											IsUncle: true,

										})
										fmt.Printf("New Uncle block %s \n", uncle.Hash().String())
									}
									return uncles
								}(),
			"isUncle":			 blockIn.IsUncle,
		}
		return bfields, nil
	}
	fields,_ := formatBlock(blockIn.Block)
	_, err := r.DB("eth_mainnet").Table("blocks").Insert(fields,r.InsertOpts{
		Conflict: "replace",
	}).RunWrite(rdb.session)
	if err != nil {
		fmt.Print(err)
		return
	}
	//fmt.Printf("%d row inserted %d", resp)
}

func NewRethinkDB ()(*Rconn) {
	_url := "localhost:28015"
	return &Rconn{
		url: _url,
	}
}