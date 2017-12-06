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



func (rdb *Rconn) InsertBlock(block *types.Block, prevTd *big.Int) {
	head := block.Header() // copies the header once
	fields := map[string]interface{}{
		"id": 				block.Hash().String(),
		"number":           hexutil.Uint64(block.Number().Uint64()),
		"hash":             block.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       hexutil.Uint64(block.Difficulty().Uint64()),
		"totalDifficulty": (*hexutil.Big)(new(big.Int).Add(block.Difficulty(), prevTd)).String(),
		"extraData":        hexutil.Bytes(head.Extra),
		"size":             hexutil.Uint64(uint64(block.Size().Int64())),
		"gasLimit":         hexutil.Uint64(block.GasLimit().Uint64()),
		"gasUsed":          hexutil.Uint64(block.GasUsed().Uint64()),
		"timestamp":        hexutil.Uint64(block.Time().Uint64()),
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}
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