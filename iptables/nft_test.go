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
	"os"
	"strings"
	"testing"
)

// vin11.nft.json / vin11.nft.txt are a real `nft -j list ruleset` /
// `nft -a list ruleset` capture from a node where iptables-save (and thus
// the old GetTables collector) silently omits the entire "filter" table,
// because it contains a NetworkPolicy chain combining two ipset matches in
// one rule - a construct the iptables-nft compat layer can't translate.
func TestParseNftRuleset_RecoversFilterTable(t *testing.T) {
	jsonData, err := os.ReadFile("vin11.nft.json")
	if err != nil {
		t.Fatal(err)
	}
	textData, err := os.ReadFile("vin11.nft.txt")
	if err != nil {
		t.Fatal(err)
	}

	tables, err := ParseNftRuleset(jsonData, textData)
	if err != nil {
		t.Fatalf("ParseNftRuleset: %+v", err)
	}

	filter, ok := tables["filter"]
	if !ok {
		t.Fatal("expected a \"filter\" table, iptables-save would have dropped it entirely")
	}

	// ip6/inet tables must not leak in: only "ip" family is handled.
	if _, ok := tables["ip6filter"]; ok {
		t.Fatal("did not expect an ip6 table to be present")
	}

	input, ok := filter["INPUT"]
	if !ok {
		t.Fatal("expected an INPUT base chain in filter")
	}
	if input.Policy != "ACCEPT" {
		t.Fatalf("expected INPUT policy ACCEPT, got %q", input.Policy)
	}
	if len(input.Rules) == 0 {
		t.Fatal("expected INPUT to have rules")
	}

	// This is the chain that iptables-nft refuses to translate
	// individually ("chain `...' in table `filter' is incompatible") -
	// find it by content rather than its hash-suffixed name, since
	// kube-router regenerates that suffix on every resync.
	var found bool
	for chainName, chain := range filter {
		if !strings.HasPrefix(chainName, "KUBE-NWPLCY-") {
			continue
		}
		for _, rule := range chain.Rules {
			if strings.Count(rule.Rule, "match-set") >= 2 {
				found = true
				if !strings.Contains(rule.Rule, "KUBE-SRC-") || !strings.Contains(rule.Rule, "KUBE-DST-") {
					t.Fatalf("rule text lost the match-set detail: %q", rule.Rule)
				}
			}
		}
	}
	if !found {
		t.Fatal("expected to find the dual match-set rule that breaks iptables-nft, but recover it via nft")
	}

	// Sanity check a plain, single-match-set rule still renders cleanly.
	services, ok := filter["KUBE-ROUTER-SERVICES"]
	if !ok {
		t.Fatal("expected KUBE-ROUTER-SERVICES chain in filter")
	}
	var sawPlainMatchSet bool
	for _, rule := range services.Rules {
		if strings.Contains(rule.Rule, "match-set kube-router-svip-prt") {
			sawPlainMatchSet = true
		}
	}
	if !sawPlainMatchSet {
		t.Fatal("expected to find the kube-router-svip-prt match-set rule")
	}
}

// vin31.nft.json / vin31.nft.txt are a real capture from a node where the
// exporter's own bundled iptables-save (v1.8.7) collapses the "raw" table's
// PRE_NOTRACK/OUT_NOTRACK rules for ports 443 and 80 into identical rule
// text ("-p tcp -j CT --notrack", dropping --dport/--sport entirely) -
// producing two Prometheus metrics with the same label set and crashing the
// exporter ("was collected before with the same name and label values").
// Reading via nft instead avoids that translation bug: it never goes
// through the legacy rule-text renderer that lost the port.
func TestParseNftRuleset_PreservesNotrackPorts(t *testing.T) {
	jsonData, err := os.ReadFile("vin31.nft.json")
	if err != nil {
		t.Fatal(err)
	}
	textData, err := os.ReadFile("vin31.nft.txt")
	if err != nil {
		t.Fatal(err)
	}

	tables, err := ParseNftRuleset(jsonData, textData)
	if err != nil {
		t.Fatalf("ParseNftRuleset: %+v", err)
	}

	raw, ok := tables["raw"]
	if !ok {
		t.Fatal("expected a \"raw\" table")
	}

	for _, chainName := range []string{"PRE_NOTRACK", "OUT_NOTRACK"} {
		chain, ok := raw[chainName]
		if !ok {
			t.Fatalf("expected chain %q in raw", chainName)
		}
		seen := make(map[string]bool)
		for _, rule := range chain.Rules {
			if seen[rule.Rule] {
				t.Fatalf("chain %q: duplicate rule text %q - this is exactly the label collision that crashed the exporter", chainName, rule.Rule)
			}
			seen[rule.Rule] = true
			if !strings.Contains(rule.Rule, "dport 443") && !strings.Contains(rule.Rule, "dport 80") &&
				!strings.Contains(rule.Rule, "sport 443") && !strings.Contains(rule.Rule, "sport 80") {
				t.Fatalf("chain %q: rule text lost its port: %q", chainName, rule.Rule)
			}
		}
	}
}
