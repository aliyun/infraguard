package schema

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRegistryNestedPropertiesAndAssociationSearch(t *testing.T) {
	r := &Registry{}
	if r.SearchAssociationProperties("x") != nil || r.GetAssociationProperty("x") != nil || r.GetSubProperties("missing", nil) != nil {
		t.Fatal("uninitialized registry returned data")
	}
	data := []byte(`{"resourceTypes":{"ALIYUN::TEST::Thing":{"properties":{"Name":{"type":"String","required":true},"Nested":{"type":"Map","properties":{"Child":{"type":"String"}}}}}}}`)
	if err := r.LoadFromData(data); err != nil {
		t.Fatal(err)
	}
	if len(r.GetSubProperties("ALIYUN::TEST::Thing", nil)) != 2 || r.GetSubProperties("ALIYUN::TEST::Thing", []string{"Nested"})["Child"] == nil || r.GetSubProperties("ALIYUN::TEST::Thing", []string{"Missing"}) != nil {
		t.Fatal("nested property lookup failed")
	}
	for _, path := range [][]string{nil, {"Missing", "Child"}, {"Name", "Child"}, {"Nested", "Missing"}} {
		if got := r.GetPropertyByPath("ALIYUN::TEST::Thing", path); got != nil {
			t.Errorf("missing property path %v: %+v", path, got)
		}
	}
	if got := r.GetPropertyByPath("ALIYUN::TEST::Thing", []string{"Nested", "Child"}); got == nil || got.Type != "String" {
		t.Fatalf("nested property: %+v", got)
	}
	if r.GetAttributes("missing") != nil || r.RequiredProperties("missing") != nil {
		t.Fatal("unknown type returned schema")
	}
	if got := r.RequiredProperties("ALIYUN::TEST::Thing"); !reflect.DeepEqual(got, []string{"Name"}) {
		t.Fatalf("required=%v", got)
	}
	r.assocSchema = &AssociationPropertyFile{AssociationProperties: map[string]*AssociationProperty{"ALIYUN::Z::Name": {}, "ALIYUN::A::Name": {}, "OTHER::Thing": {}}}
	if got := r.SearchAssociationProperties("name"); !reflect.DeepEqual(got, []string{"ALIYUN::A::Name", "ALIYUN::Z::Name"}) {
		t.Fatalf("search=%v", got)
	}
	if got := r.SearchAssociationProperties("absent"); len(got) != 0 {
		t.Fatalf("unexpected search=%v", got)
	}
}

func TestSaveLocalWithNoHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if err := SaveLocal([]byte(`{}`)); err == nil {
		t.Fatal("missing home accepted")
	}
}

func TestUninitializedRegistryAndBlockedSchemaDirectory(t *testing.T) {
	r := &Registry{}
	if r.Version() != "" || r.ResourceTypeCount() != 0 || r.GetResourceType("missing") != nil || r.AllResourceTypeNames() != nil || r.SearchResourceTypes("x") != nil || r.AllAssociationPropertyNames() != nil {
		t.Fatal("empty registry returned schema data")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".infraguard"), []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveLocal([]byte(`{}`)); err == nil {
		t.Fatal("schema directory created under a file")
	}
}
