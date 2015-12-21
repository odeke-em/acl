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

package scope

import (
	"fmt"
	"strings"

	"github.com/odeke-em/acl/common"
)

const Separator = ":"

type Scope uint64

const (
	UnknownScope Scope = 0
	Public       Scope = 1 << iota
	Private
	User
	Group
	Domain
	Organization
)

const unknownScopeStr = "unknownScope"

var stoaMap = map[Scope]string{
	Public:       "public",
	Private:      "private",
	User:         "user",
	Group:        "group",
	Domain:       "domain",
	Organization: "organization",
}

var atosMap = func() (oom map[string]Scope) {
	oom = make(map[string]Scope)

	for k, v := range stoaMap {
		oom[v] = k
	}

	return oom
}()

func stoa(s Scope) string {
	retr, ok := stoaMap[s]
	if !ok {
		return unknownScopeStr
	}

	return retr
}

func atos(s string) (Scope, error) {
	retr, ok := atosMap[s]
	if !ok {
		return UnknownScope, fmt.Errorf("unknownScope for %v", s)
	}

	return retr, nil
}

func Atos(s string) (sc Scope, err error) {
	trimmed := strings.Trim(s, " ")
	if len(trimmed) < 1 {
		return UnknownScope, fmt.Errorf("unknownScope for %v", s)
	}

	splits := strings.Split(trimmed, Separator)

	for _, splitRaw := range splits {
		// Expecting a format like:
		//     "public:private:organization"
		//     "private:user"
		split := strings.Trim(splitRaw, " ")
		if split == "" {
			continue
		}
		result, resolvErr := atos(split)
		if resolvErr != nil {
			err = common.ReComposeError(err, resolvErr.Error())
		} else {
			sc |= result
		}
	}

	return
}

func (sc Scope) String() string {
	if sc == UnknownScope { // TODO: Sanity check enforcement ts ensure UnknownScope is always "0"
		return stoa(sc)
	}

	sects := []string{}
	for si := Scope(1); si <= sc; si <<= 1 {
		val := si & sc
		if val == 0 {
			continue
		}

		sects = append(sects, stoa(val))
	}

	return strings.Join(sects, Separator)
}
