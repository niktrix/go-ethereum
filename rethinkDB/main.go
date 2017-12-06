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
	"fmt"
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
	if err != nil {
		fmt.Print(err)
	}
	if err == nil{
		rdb.session = session
	}
	return  err
}

func (rdb *Rconn) Sample_insert(id int) {
	type Post struct {
		ID      int    `gorethink:"id"`
		Title   string `gorethink:"title"`
		Content string `gorethink:"content"`
	}

	resp, err := r.DB("examples").Table("posts").Insert(Post{
		ID:      id,
		Title:   "Lorem ipsum",
		Content: "Dolor sit amet",
	}).RunWrite(rdb.session)
	if err != nil {
		fmt.Print(err)
		return
	}

	fmt.Printf("%d row inserted", resp.Inserted)
}

func NewRethinkDB () (*Rconn) {
	return &Rconn{}
}