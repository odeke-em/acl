// Copyright 2015 Emmanuel Odeke. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acl

import (
	"testing"
)

func TestStoaValidValuesWithGrouping(t *testing.T) {
	cases := []struct {
		value    string
		keyCount int
	}{
		{value: "private-execute:organization:organization", keyCount: 2},
		{value: "public-write|read|execute:private-execute:private:public", keyCount: 2},
		{value: "public:organization:private:group:group-execute|read|write", keyCount: 4},
	}

	for _, tc := range cases {
		ac, err := Stoa(tc.value)
		if err != nil {
			t.Errorf("a non-nil err %v was returned for value %q", err, tc.value)
		}

		if ac == nil {
			t.Errorf("a nil acl was returned for %q", tc.value)
		}

		if kc := len(ac.rules); kc != tc.keyCount {
			t.Errorf("expected a keyCount of %v, instead got %v", tc.keyCount, kc)
		}
	}
}

func TestStoaValidValuesWithInvalidPermissions(t *testing.T) {
	cases := []string{
		"private-executex:organization-user:organization:user",
		"public-w|r|x:private-exec:private:pub",
	}

	for _, tc := range cases {
		ac, err := Stoa(tc)
		if err == nil {
			t.Errorf("bad value %q passed with no err, expected a non-nil err", tc)
		}

		if ac == nil {
			t.Errorf("expected a non-nil acl for %q", tc)
		}
	}
}