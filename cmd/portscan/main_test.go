/**
 * @author Blue Thunder Somogyi
 *
 * Copyright (c) 2016 Blue Thunder Somogyi
 */
package main

import (
	"sort"
	"testing"
)

// TestOutputKeys exercises sorting of OutputKey types
func TestOutputKeys(t *testing.T) {
	ok := make(OutputKeys, 0)
	ok = append(ok, OutputKey{Addr: "abc", Port: 123})
	if ok[0].Addr != "abc" || ok[0].Port != 123 {
		t.Fail()
	}

	ok = append(ok, OutputKey{Addr: "xyz", Port: 789})
	if ok[1].Addr != "xyz" || ok[1].Port != 789 {
		t.Fail()
	}

	ok = append(ok, OutputKey{Addr: "mno", Port: 456})
	if ok[2].Addr != "mno" || ok[2].Port != 456 {
		t.Fail()
	}

	sort.Sort(ok)

	for idx, key := range ok {
		switch {
		case idx == 0 && key.String() != "abc:123":
			t.Log("idx == 0 && key.String() != 'abc:123'")
			t.Fail()
		case idx == 1 && key.String() != "mno:456":
			t.Log("idx == 1 && key.String() != 'mno:456'")
			t.Fail()
		case idx == 2 && key.String() != "xyz:789":
			t.Log("idx == 2 && key.String() != 'xyz:789'")
			t.Fail()
		}
	}
}

// TestOutputMap exercises OutputMap sorting
func TestOutputMap(t *testing.T) {
	OutputMap = make(map[OutputKey]string)
	keys := make(OutputKeys, 0)

	newKey := OutputKey{Addr: "mno", Port: 456}
	OutputMap[newKey] = newKey.String()
	keys = append(keys, newKey)

	newKey = OutputKey{Addr: "xyz", Port: 789}
	OutputMap[newKey] = newKey.String()
	keys = append(keys, newKey)

	newKey = OutputKey{Addr: "abc", Port: 123}
	OutputMap[newKey] = newKey.String()
	keys = append(keys, newKey)

	sort.Sort(keys)

	for idx, key := range keys {
		switch {
		case idx == 0 && OutputMap[key] != "abc:123":
			t.Log("idx == 0 && OutputMap[key] != 'abc:123'")
			t.Fail()
		case idx == 1 && OutputMap[key] != "mno:456":
			t.Log("idx == 0 && OutputMap[key] != 'mno:456'")
			t.Fail()
		case idx == 2 && OutputMap[key] != "xyz:789":
			t.Log("idx == 0 && OutputMap[key] != 'xyz:789'")
			t.Fail()
		}
	}
}
