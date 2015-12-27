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
	"fmt"
	"testing"

	"github.com/odeke-em/acl/permission"
)

func TestStoaValidValuesWithGrouping(t *testing.T) {
	cases := []struct {
		value    string
		keyCount int
	}{
		{value: ":::private-execute:organization:organization", keyCount: 2},
		{value: "public:::private-write|read|execute:private-execute||||||read:private:public-------------", keyCount: 2},
		{value: "public:organization:private:group:group-execute|read|write:::::::::::", keyCount: 4},
		{value: "fd0389bf928e4fa4a70696ab85552f11:::private-write|read|execute:private-execute||||||read:private:public-------------", keyCount: 3},
		{value: "exampleorg.com-execute:organization:organization", keyCount: 2},
		{value: "11083811380-execute|read|write", keyCount: 1},
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
			t.Errorf("%q %v expected a keyCount of %v, instead got %v", tc.value, ac.rules, tc.keyCount, kc)
		}
	}
}

func TestStoaValidValuesWithInvalidPermissions(t *testing.T) {
	cases := []string{
		"private-executex:organization-user:organization:user",
		"public-w|r|x:private-exec:private-------------xm:pub",
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

func TestACLString(t *testing.T) {
	cases := []string{
		"private-execute:organization:organization:public-read|write|execute|list",
		"public-write|read|execute:private-execute:private:public",
		"public:organization:private:group:group-execute|read|write:::::::::::::::",
	}

	for _, tc := range cases {
		ac, err := Stoa(tc)
		if err != nil {
			t.Errorf("a non-nil err %v was returned for value %q", err, tc)
		}

		if ac == nil {
			t.Errorf("a nil acl was returned for %q", tc)
		}

		if false {
			fmt.Printf("***\n%s\n***\n", ac)
		}
	}
}

func BenchmarkACLString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cases := []string{
			"private-execute:organization:organization:public-read|write|execute|list",
			"public-write|read|execute:private-execute:private:public",
			"public:organization:private:group:group-execute|read|write",
		}

		for _, tc := range cases {
			ac, err := Stoa(tc)
			if err != nil {
				b.Errorf("a non-nil err %v was returned for value %q", err, tc)
			}

			if ac == nil {
				b.Errorf("a nil acl was returned for %q", tc)
			}

			aclStr := ac.String()
			if len(aclStr) < 1 {
				b.Errorf("given an acl %q got %q of length %v", tc, aclStr, len(aclStr))
			}
		}
	}
}

func nUUIDs(n int) []string {
	uids := []string{}
	for i := 0; i < n; i++ {
		uids = append(uids, newUUID())
	}
	return uids
}

func TestRegisterUser(t *testing.T) {
	uids := nUUIDs(6)

	acl := Acl{}
	for _, uid := range uids {
		err := acl.RegisterUser(uid)
		if err != nil {
			t.Errorf("err %v for uid %q", err, uid)
		}
	}

	// Round 2 of insertions
	for _, uid := range uids {
		err := acl.RegisterUser(uid)
		if err == nil {
			t.Errorf("prior insertion %v for uid %q", ErrUserAlreadyExists, uid)
		}
	}
}

func TestDeRegister(t *testing.T) {
	n := 6
	uids := nUUIDs(n)

	acl := Acl{}
	for i := 0; i < n; i++ {
		for _, uid := range uids {
			err := acl.DeRegisterUser(uid)
			if err == nil {
				t.Errorf("iter #%d uid %q expected a non-nil err", i, uid)
			}
		}
	}
}

func TestRegisterDeRegisterForPlainACL(t *testing.T) {
	n := 6
	uids := nUUIDs(n)

	acl := Acl{}
	for _, uid := range uids {
		err := acl.DeRegisterUser(uid)
		if err == nil {
			t.Errorf("deRegister: uid %q expected a non-nil err", uid)
		}

		err = acl.RegisterUser(uid)
		if err != nil {
			t.Errorf("register uid %q expected success, got %v", uid, err)
		}

		err = acl.DeRegisterUser(uid)
		if err != nil {
			t.Errorf("deRegister uid %q expected success, got %v", uid, err)
		}

		err = acl.DeRegisterUser(uid)
		if err == nil {
			t.Errorf("second deRegister: uid %q expected failure", uid)
		}
	}
}

func TestRegisterDeRegisterForInitedACL(t *testing.T) {
	n := 6
	uids := nUUIDs(n)

	acl, err := New("")
	if err != nil {
		t.Errorf("expected a successful acl.New(...), got %v", err)
	}

	for _, uid := range uids {
		err := acl.DeRegisterUser(uid)
		if err == nil {
			t.Errorf("deRegister: uid %q expected a non-nil err", uid)
		}

		err = acl.RegisterUser(uid)
		if err != nil {
			t.Errorf("register uid %q expected success, got %v", uid, err)
		}

		err = acl.DeRegisterUser(uid)
		if err != nil {
			t.Errorf("deRegister uid %q expected success, got %v", uid, err)
		}

		err = acl.DeRegisterUser(uid)
		if err == nil {
			t.Errorf("second deRegister: uid %q expected failure", uid)
		}
	}
}

func TestInsertAndRemovePermissions(t *testing.T) {
	acl := Acl{}

	uid := "pronto"
	perms := []permission.Permission{
		permission.Read, permission.Write, permission.Delete,
	}
	_, err := acl.Insert(uid, perms...)
	if err == nil {
		t.Errorf("did not pre-register user %q", uid)
	}

	_, _, err = acl.Remove(uid, perms...)
	if err == nil {
		t.Errorf("did not pre-register user %q", uid)
	}

	if err := acl.RegisterUser(uid); err != nil {
		t.Errorf("expected success registering user %q, instead got %v", uid, err)
	}

	inserted, iErr := acl.Insert(uid, perms...)
	if iErr != nil {
		t.Errorf("should have successfully inserted user %q got %v", uid, err)
	}

	if il, pl := len(inserted), len(perms); il != pl {
		t.Errorf("insertedLength (%d) != permissionsLength (%d)", il, pl)
	}

	_, _, err = acl.Remove(uid, perms...)
	if err != nil {
		t.Errorf("err: %v expected successful remova for user %q perms %s", err, uid, perms)
	}
}

func TestCheckUninitialized(t *testing.T) {
	acl := Acl{}
	uid := "ingredient"
	perms := []permission.Permission{
		permission.Delete, permission.Write,
	}

	for i := 0; i < 10; i++ {
		_, _, err := acl.Check(uid, perms...)
		if err == nil {
			t.Errorf("#%d check: %s did not expect success with perms %v", i, uid, perms)
		}
	}
}

func TestCheck(t *testing.T) {
	acl := Acl{}
	uid := "ingredient"
	perms := []permission.Permission{
		permission.Delete, permission.Write,
	}
	notSetPerm := permission.Read

	if err := acl.RegisterUser(uid); err != nil {
		t.Errorf("%s expected success got %v", uid, err)
	}

	inserted, err := acl.Insert(uid, perms...)
	if err != nil {
		t.Errorf("insertion of %v expected success got %v", perms, err)
	}

	if il, pl := len(inserted), len(perms); il != pl {
		t.Errorf("insertedLen: %d permissions %d", il, pl)
	}

	allChecked := append(perms[:], notSetPerm)

	for i := 0; i < 10; i++ {
		wasSet, notSet, err := acl.Check(uid, allChecked...)
		if err != nil {
			t.Errorf("#%d check: %s expected no errors with perms %v, got %v", i, uid, perms, err)
		}

		if wl, pl := len(wasSet), len(perms); wl != pl {
		    t.Errorf("wasSet(%v) != perms(%v)", wasSet, perms)
		}

		if nl := len(notSet); nl != 1 {
		    t.Errorf("notSet(%v) len: %d expected 1", notSet, nl)
		}
	}
}
