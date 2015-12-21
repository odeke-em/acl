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
	"sort"
	"strings"

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

var emptyStruct = struct{}{}

type rulesMap map[scope.Scope]map[permission.Permission]struct{}

type Acl struct {
	rules rulesMap
	ttl   int64
	name  string
	uuid  string
}

func Stoa(s string) (aclV *Acl, err error) {
	aclV = &Acl{
		rules: make(rulesMap),
		uuid:  uuid.UUID4().String(),
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
