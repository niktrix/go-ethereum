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
	_ "math/big"
	_ "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	_"math/big"
	"math/big"
	"github.com/ethereum/go-ethereum/core/state"
)

type Rconn struct {
	url string
	session *r.Session
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



func (rdb *Rconn) InsertBlock(block *types.Block, state *state.StateDB, prevTd *big.Int) {//prevTd *big.Int) {
	formatBlock := func(b *types.Block) (map[string]interface{}, error) {
		head := b.Header() // copies the header once
		minerBalance := state.GetBalance(head.Coinbase)
		bfields := map[string]interface{}{
			"id": 				block.Hash().String(),
			"number":           head.Number.String(),
			"intNumber":        hexutil.Uint64(head.Number.Uint64()),
			"hash":             b.Hash().String(),
			"parentHash":       head.ParentHash.String(),
			"nonce":            hexutil.Uint64(head.Nonce.Uint64()).String(),
			"mixHash":          head.MixDigest.String(),
			"sha3Uncles":       head.UncleHash.String(),
			"logsBloom":        hexutil.Bytes(head.Bloom.Bytes()).String(),
			"stateRoot":        head.Root.String(),
			"miner":            head.Coinbase.String(),
			"minerBalance":     (*hexutil.Big)(minerBalance).String(),
			"difficulty":       (*hexutil.Big)(head.Difficulty).String(),
			"totalDifficulty":  (*hexutil.Big)(new(big.Int).Add(block.Difficulty(), prevTd)).String(),
			"extraData":        hexutil.Bytes(head.Extra).String(),
			"size":             hexutil.Uint64(uint64(b.Size().Int64())).String(),
			"gasLimit":         (*hexutil.Big)(head.GasLimit).String(),
			"gasUsed":          (*hexutil.Big)(head.GasUsed).String(),
			"timestamp":        (*hexutil.Big)(head.Time).String(),
			"transactionsRoot": head.TxHash.String(),
			"receiptsRoot":     head.ReceiptHash.String(),
		}
		return bfields, nil
	}
	fields,_ := formatBlock(block)
	resp, err := r.DB("eth_mainnet").Table("blocks").Insert(fields).RunWrite(rdb.session)
	if err != nil {
		fmt.Print(err)
		return
	}

	fmt.Printf("%d row inserted %d", resp)
}

func NewRethinkDB ()(*Rconn) {
	_url := "localhost:28015"
	return &Rconn{
		url: _url,
	}
}