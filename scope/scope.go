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

type Scope struct {
	value string
}

const unknownScopeStr = "unknownScope"

var UnknownScope = Scope{value: unknownScopeStr}

func stoa(s Scope) string {
	return s.value
}

func atos(s string) (Scope, error) {
	// TODO: Specify what values can be entered into a Scope
	trimmed := strings.Trim(s, " ")
	if len(trimmed) < 1 {
		return UnknownScope, fmt.Errorf("unknownScope for %v", s)
	}

	return Scope{value: s}, nil
}

func New(s string) (Scope, error) {
  return Atos(s)
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
		//     "118791237492:user"
		split := strings.Trim(splitRaw, " ")
		if split == "" {
			continue
		}
		result, resolvErr := atos(split)
		if resolvErr != nil {
			err = common.ReComposeError(err, resolvErr.Error())
		} else {
			sc.Combine(result)
		}
	}

	return
}

func (sc *Scope) Combine(other Scope) {
	first, rest := sc.value, other.value
	if first == "" {
	  first = rest
	} else if rest != "" {
	  first =  fmt.Sprintf("%s%s%s", first, Separator, rest)
	}
	sc.value = first
}

func (sc Scope) String() string {
	if sc == UnknownScope { // TODO: Sanity check enforcement ts ensure UnknownScope is always "0"
		return stoa(sc)
	}

	return sc.value
}
