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

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// GetTablesNft reads the current ruleset via nft instead of iptables-save.
//
// iptables-save (through the iptables-nft compat layer) silently drops an
// entire table from its output the moment a single rule in that table uses
// an nftables construct it can't translate back to legacy syntax (e.g. two
// ipset matches in one rule, or a combined rate-limit+log statement) - with
// no error on stderr, so a caller has no way to detect the gap. nft itself
// has no such limitation, so this reads the ruleset through nft instead.
func GetTablesNft() (Tables, error) {
	jsonOut, err := exec.Command("nft", "-j", "list", "ruleset").Output()
	if err != nil {
		return nil, fmt.Errorf("nft -j list ruleset: %w", err)
	}
	textOut, err := exec.Command("nft", "-a", "list", "ruleset").Output()
	if err != nil {
		return nil, fmt.Errorf("nft -a list ruleset: %w", err)
	}
	return ParseNftRuleset(jsonOut, textOut)
}

// Only the "ip" (IPv4) family is considered, matching the original
// iptables-save-based collector, which never looked at ip6tables either.
const nftFamily = "ip"

type nftListing struct {
	Nftables []nftItem `json:"nftables"`
}

type nftItem struct {
	Table *nftJSONTable `json:"table"`
	Chain *nftJSONChain `json:"chain"`
	Rule  *nftJSONRule  `json:"rule"`
}

type nftJSONTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type nftJSONChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

type nftJSONRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Handle uint64            `json:"handle"`
	Expr   []json.RawMessage `json:"expr"`
}

type nftJSONCounter struct {
	Counter *struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counter"`
}

// ParseNftRuleset builds a Tables model from the outputs of
// `nft -j list ruleset` (structure and counters) and `nft -a list ruleset`
// (human-readable rule text, correlated back to JSON rules by handle).
//
// Chain-level Packets/Bytes (hits on a chain's default policy, when no rule
// matched) are always left at 0: nft doesn't track that unless an explicit
// counter statement is attached to the policy, which kube-router/iptables-nft
// don't do - the same fields were already always 0 under the previous
// iptables-save-based collector for this reason.
func ParseNftRuleset(jsonData, textData []byte) (Tables, error) {
	var listing nftListing
	if err := json.Unmarshal(jsonData, &listing); err != nil {
		return nil, fmt.Errorf("parsing nft json: %w", err)
	}

	ruleText, err := parseNftText(textData)
	if err != nil {
		return nil, fmt.Errorf("parsing nft text: %w", err)
	}

	result := make(Tables)
	for _, item := range listing.Nftables {
		switch {
		case item.Table != nil:
			if item.Table.Family != nftFamily {
				continue
			}
			if _, ok := result[item.Table.Name]; !ok {
				result[item.Table.Name] = make(Table)
			}
		case item.Chain != nil:
			c := item.Chain
			if c.Family != nftFamily {
				continue
			}
			table := result[c.Table]
			if table == nil {
				table = make(Table)
				result[c.Table] = table
			}
			policy := "-"
			if c.Policy != "" {
				policy = strings.ToUpper(c.Policy)
			}
			table[c.Name] = Chain{Policy: policy}
		case item.Rule != nil:
			r := item.Rule
			if r.Family != nftFamily {
				continue
			}
			table := result[r.Table]
			if table == nil {
				table = make(Table)
				result[r.Table] = table
			}
			chain := table[r.Chain]
			packets, bytes := extractNftCounter(r.Expr)
			chain.Rules = append(chain.Rules, Rule{
				Packets: packets,
				Bytes:   bytes,
				Rule:    ruleText[nftRuleKey{table: r.Table, chain: r.Chain, handle: r.Handle}],
				Handle:  r.Handle,
			})
			table[r.Chain] = chain
		}
	}
	return result, nil
}

func extractNftCounter(expr []json.RawMessage) (packets, bytes uint64) {
	for _, raw := range expr {
		var c nftJSONCounter
		if err := json.Unmarshal(raw, &c); err == nil && c.Counter != nil {
			return c.Counter.Packets, c.Counter.Bytes
		}
	}
	return 0, 0
}

type nftRuleKey struct {
	table  string
	chain  string
	handle uint64
}

var (
	nftTableHeaderRe = regexp.MustCompile(`^table (\S+) (\S+) \{`)
	nftChainHeaderRe = regexp.MustCompile(`^chain (\S+) \{`)
	nftRuleHandleRe  = regexp.MustCompile(`# handle (\d+)\s*$`)
	nftCounterRe     = regexp.MustCompile(`\bcounter packets \d+ bytes \d+\s*`)
)

// parseNftText walks the pretty-printed `nft -a list ruleset` output and
// returns, for every rule, the human-readable text nft itself rendered for
// it - including its fallback "# match-set ..." style comments for rule
// expressions nft can't otherwise name. That text is used as-is for the
// Prometheus "rule" label; it intentionally doesn't try to reconstruct
// legacy iptables rule syntax.
func parseNftText(data []byte) (map[nftRuleKey]string, error) {
	result := make(map[nftRuleKey]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var family, table, chain string
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := nftLeadingTabs(line)

		switch {
		case indent == 0 && nftTableHeaderRe.MatchString(trimmed):
			m := nftTableHeaderRe.FindStringSubmatch(trimmed)
			family, table = m[1], m[2]
		case indent == 0 && trimmed == "}":
			family, table, chain = "", "", ""
		case indent == 1 && nftChainHeaderRe.MatchString(trimmed):
			chain = nftChainHeaderRe.FindStringSubmatch(trimmed)[1]
		case indent == 1 && trimmed == "}":
			chain = ""
		case indent >= 2 && chain != "" && nftRuleHandleRe.MatchString(trimmed):
			if family != nftFamily {
				continue
			}
			hm := nftRuleHandleRe.FindStringSubmatch(trimmed)
			handle, err := strconv.ParseUint(hm[1], 10, 64)
			if err != nil {
				continue
			}
			text := nftRuleHandleRe.ReplaceAllString(trimmed, "")
			text = nftCounterRe.ReplaceAllString(text, "")
			text = strings.Join(strings.Fields(text), " ")
			result[nftRuleKey{table: table, chain: chain, handle: handle}] = text
		}
	}
	return result, scanner.Err()
}

func nftLeadingTabs(s string) int {
	n := 0
	for n < len(s) && s[n] == '\t' {
		n++
	}
	return n
}
