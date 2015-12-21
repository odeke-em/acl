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

package permission

import (
	"fmt"
	"strings"

	"github.com/odeke-em/acl/common"
)

type Permission uint64

const (
	None Permission = 0
	List Permission = 1 << iota
	Read
	Write
	Execute
	Delete
)

const Separator = "|"
const UnknownStr = "unknown"

var ptoaMap = map[Permission]string{
	None:    "none",
	List:    "list",
	Write:   "write",
	Delete:  "delete",
	Read:    "read",
	Execute: "execute",
}

var atopMap = func() (revMap map[string]Permission) {
	revMap = make(map[string]Permission)
	for k, v := range ptoaMap {
		revMap[v] = k
	}
	return revMap
}()

// ptoa returns the unit permission string representation
func ptoa(p Permission) string {
	// Since no writes affect either the ptoaMap or
	// atopMap, no need to lock any of them
	repr, ok := ptoaMap[p]
	if !ok {
		return UnknownStr
	}

	return repr
}

// Atop returns the Permission whose bits are set by the
// different representations of the word values
func Atop(s string) (p Permission, err error) {
	splits := strings.Split(s, Separator)
	for _, strRaw := range splits {
		str := strings.Trim(strRaw, " ")
		if str == "" {
			continue
		}
		result, resolvErr := atop(str)
		if resolvErr != nil {
			err = common.ReComposeError(err, resolvErr.Error())
		} else {
			p |= result
		}
	}

	return
}

func (p Permission) String() string {
	if p == None { // TODO: Sanity check enforcement to ensure None is always "0"
		return ptoa(p)
	}

	sects := []string{}

	for i := Permission(1); i <= p; i <<= 1 {
		result := p & i
		if result == 0 {
			continue
		}
		extracted := Permission(p & i)
		sects = append(sects, ptoa(extracted))
	}

	return strings.Join(sects, Separator)
}

type Permissioner struct {
	Set    func(Permission) Permission
	Unset  func(Permission) Permission
	WasSet func(Permission) bool
}

func powerOfTwo(p Permission) bool {
	return p != 0 && ((p & (p - 1)) == 0)
}

func ClearedOrLonePermission(p Permission) bool {
	return p == None || powerOfTwo(p)
}

func unitPermPermissioner(p Permission) *Permissioner {
	if !ClearedOrLonePermission(p) {
		panic("either the zeroth or only one bit has to be set, uniquely")
	}

	return &Permissioner{
		Set: func(q Permission) Permission {
			return p | q
		},
		Unset: func(q Permission) Permission {
			return q & (^q)
		},
		WasSet: func(q Permission) bool {
			return (p & q) != 0
		},
	}
}

var (
	NonePermissioner    = unitPermPermissioner(None)
	ListPermissioner    = unitPermPermissioner(List)
	ReadPermissioner    = unitPermPermissioner(Read)
	DeletePermissioner  = unitPermPermissioner(Delete)
	WritePermissioner   = unitPermPermissioner(Write)
	ExecutePermissioner = unitPermPermissioner(Execute)
)

func atop(s string) (Permission, error) {
	repr, ok := atopMap[s]
	if !ok {
		return None, fmt.Errorf("unknown permission %q", s)
	}

	return repr, nil
}
