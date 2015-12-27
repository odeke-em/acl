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
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/odeke-em/acl/common"
	"github.com/odeke-em/acl/permission"
	"github.com/odeke-em/acl/scope"
	"github.com/odeke-em/go-uuid"
)

const (
	ruleSeparator       = "\n"
	scopeDelimiter      = ":"
	permissionDelimiter = "-"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserDoesnotExist  = errors.New("user does not exist")
	ErrUninitializedACL  = errors.New("uninitialized ACL")
)

var emptyStruct = struct{}{}

type rulesMap map[scope.Scope]map[permission.Permission]struct{}

type Acl struct {
	rules rulesMap
	ttl   int64
	name  string
	uuid  string
	mu    sync.Mutex
}

func New(s string) (aclV *Acl, err error) {
	return Stoa(s)
}

func newUUID() string {
	return uuid.UUID4().String()
}

func Stoa(s string) (aclV *Acl, err error) {
	aclV = &Acl{
		rules: make(rulesMap),
	}

	rules := strings.Split(s, ruleSeparator)
	for _, rule := range rules {
		trimmed := strings.Trim(rule, " ")
		if rule == "" {
			continue
		}

		scopeDelimits := strings.Split(trimmed, scopeDelimiter)
		for _, scopeDelim := range scopeDelimits {
			scTrimmed := strings.Trim(scopeDelim, " ")
			if scTrimmed == "" {
				continue
			}
			scopePermissions := strings.Split(scTrimmed, permissionDelimiter)
			count := len(scopePermissions)
			if count < 1 {
				continue
			}

			first, rest := scopePermissions[0], scopePermissions[1:]

			scFromS, scErr := scope.Atos(first)
			if scErr != nil {
				err = common.ReComposeError(err, fmt.Sprintf("scopeStr: %q err: %s", first, scErr.Error()))
				continue
			}

			retr, ok := aclV.rules[scFromS]
			if !ok {
				retr = make(map[permission.Permission]struct{})
			}

			for _, permStr := range rest {
				permTrimmed := strings.Trim(permStr, " ")
				if permTrimmed == "" {
					continue
				}
				perm, permErr := permission.Atop(permStr)
				if permErr != nil {
					err = common.ReComposeError(err, fmt.Sprintf("permStr: %q err: %s", permStr, permErr.Error()))
					continue
				}

				retr[perm] = emptyStruct
			}

			aclV.rules[scFromS] = retr
		}
	}

	return
}

func (a *Acl) String() string {
	if a == nil {
		return "[nil]"
	}

	remapped := make(map[string]string)

	keys := []string{}
	for sscope, permissionMap := range a.rules {
		scopeStr := sscope.String()

		permRemap := []string{}
		for perm, _ := range permissionMap {
			permRemap = append(permRemap, perm.String())
		}

		sort.Sort(sort.StringSlice(permRemap))

		remapped[scopeStr] = strings.Join(permRemap, permission.Separator)
		keys = append(keys, scopeStr)
	}

	sort.Sort(sort.StringSlice(keys))

	all := []string{}
	for _, key := range keys {
		retr, _ := remapped[key]

		repr := key
		if len(retr) >= 1 {
			repr = fmt.Sprintf("%s%s%s", repr, permissionDelimiter, retr)
		}
		all = append(all, repr)
	}

	return strings.Join(all, ruleSeparator)
}

func (a *Acl) Remove(userId string, permissions ...permission.Permission) (pass, fail []permission.Permission, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// TODO: Potential caching for userId lookups and conversions
	sc, scErr := scope.New(userId)
	if scErr != nil {
		err = scErr
		return
	}

	permMap, ok := a.rules[sc]
	if !ok {
		err = fmt.Errorf("no such userId %q found", userId)
		return
	}

	alreadyRemoved := map[permission.Permission]struct{}{}
	for _, perm := range permissions {
		ptr := &fail
		if _, ok := permMap[perm]; ok {
			delete(permMap, perm)
			alreadyRemoved[perm] = emptyStruct
			ptr = &pass
		} else if _, ok := alreadyRemoved[perm]; ok {
			ptr = &pass
		}

		*ptr = append(*ptr, perm)
	}

	return
}

func (a *Acl) RegisterUser(userId string) (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, scErr := scope.New(userId)
	if scErr != nil {
		err = scErr
		return
	}

	if a.rules == nil {
		a.rules = make(rulesMap)
	}

	if _, ok := a.rules[sc]; ok {
		return ErrUserAlreadyExists
	}

	a.rules[sc] = make(map[permission.Permission]struct{})
	return
}

func (a *Acl) DeRegisterUser(userId string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.rules == nil {
		return ErrUninitializedACL
	}

	sc, scErr := scope.New(userId)
	if scErr != nil {
		return scErr
	}

	if _, ok := a.rules[sc]; !ok {
		return ErrUserDoesnotExist
	}

	delete(a.rules, sc)
	return nil
}

func (a *Acl) Insert(userId string, permissions ...permission.Permission) (added []permission.Permission, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	sc, scErr := scope.New(userId)
	if scErr != nil {
		err = scErr
		return
	}

	permMap, ok := a.rules[sc]
	if !ok {
		err = fmt.Errorf("no such userId %q found", userId)
		return
	}

	for _, perm := range permissions {
		if _, ok := permMap[perm]; !ok {
			added = append(added, perm)
			permMap[perm] = emptyStruct
		}
	}

	return
}

func (a *Acl) Check(userId string, permissions ...permission.Permission) (wasSet, notSet []permission.Permission, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.rules == nil {
		err = ErrUninitializedACL
		return
	}

	sc, scErr := scope.New(userId)
	if scErr != nil {
		err = scErr
		return
	}

	permMap, ok := a.rules[sc]
	if !ok {
		err = ErrUserDoesnotExist
		return
	}

	for _, perm := range permissions {
		ptr := &notSet
		if _, ok := permMap[perm]; ok {
			ptr = &wasSet
		}

		*ptr = append(*ptr, perm)
	}

	return
}
