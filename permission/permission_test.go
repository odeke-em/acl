package permission

import (
	"testing"
)

func TestReadPermissioner(t *testing.T) {
	if ReadPermissioner == nil {
		t.Errorf("ReadPermissioner is nil")
	}

	nonNilExpectations := map[string]interface{}{
		"Set":   ReadPermissioner.Set,
		"Unset": ReadPermissioner.Unset,
		"WasSet":    ReadPermissioner.WasSet,
	}

	for k, v := range nonNilExpectations {
		if v == nil {
			t.Errorf("method:%q cannot be nil", k)
		}
	}
}

func TestClearedOrLonePermission(t *testing.T) {
	if ClearedOrLonePermission(None) != true {
		t.Errorf("the 'None' permission should always be cleared and void of any value")
	}

	cases := []struct {
		name  string
		value Permission
		want  bool
	}{
		{name: "none", value: None, want: true},
		{name: "read", value: Read, want: true},
		{name: "write", value: Write, want: true},
		{name: "delete", value: Delete, want: true},
		{name: "execute", value: Execute, want: true},
		{name: "execute|delete", value: Execute | Delete, want: false},
		{name: "read|write|execute|delete", value: Read | Write | Execute | Delete, want: false},
	}

	for _, tc := range cases {
		got := ClearedOrLonePermission(tc.value)
		if got != tc.want {
			t.Errorf("%q wanted %v got %v", tc.name, tc.want, got)
		}

		repr := tc.value.String()
		if repr != tc.name {
			t.Errorf("wanted %q, got %q", tc.name, repr)
		}
	}
}

func TestSet(t *testing.T) {
	mapping := map[Permission]*Permissioner{
		Read:    ReadPermissioner,
		Write:   WritePermissioner,
		Execute: ExecutePermissioner,
		Delete:  DeletePermissioner,
		List:    ListPermissioner,
	}

	cases := []Permission{
		Read | Write | Execute,
		None,
	}

	for perm, permSt := range mapping {
		if permSt == nil {
			t.Errorf("%q permSt cannot be nil", perm)
		}

		cleanSlate := None
		got := permSt.Set(cleanSlate)
		if got != perm {
			t.Errorf("with a clean slate of %q, invoking Set for %q should give %q, got %q", cleanSlate, perm, perm, got)
		}

		if !permSt.WasSet(got) {
			t.Errorf("for %q expected %q bit to have been set", got, perm)
		}

		cleared := permSt.Unset(cleanSlate)
		if cleared != cleanSlate {
			t.Errorf("once cleared expected a revert to %q, instead got %q", cleanSlate, cleared)
		}

		for _, _ = range cases {
		}
	}
}
