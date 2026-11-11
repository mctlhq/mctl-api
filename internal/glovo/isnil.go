package glovo

import "reflect"

// IsNil is true for an untyped nil and for a nil pointer, map, slice, func,
// interface or channel held in an interface value: a nil *pgxpool.Pool stored
// in an interface is a missing collaborator, not a working one.
func IsNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface, reflect.Chan:
		return rv.IsNil()
	}
	return false
}
