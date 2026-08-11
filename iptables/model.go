// Copyright 2018 RetailNext, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

type Tables map[string]Table

type Table map[string]Chain

type Chain struct {
	Policy  string
	Packets uint64
	Bytes   uint64
	Rules   []Rule
}

type Rule struct {
	Packets uint64
	Bytes   uint64
	Rule    string
	// Handle is the nft rule handle (0 when the data came from
	// iptables-save, which has no such concept). Unlike Rule, which is
	// free-form text nft renders and can render identically for two
	// distinct rules when it can't fully decode a match (e.g. two
	// separate ipset matches both falling back to the same generic
	// `xt match "set"` placeholder), the handle is always unique within
	// a chain - it's what lets the exporter tell such rules apart.
	Handle uint64
}
