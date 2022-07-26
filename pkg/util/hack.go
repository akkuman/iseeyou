package util

import (
	"reflect"
	"unsafe"
)

// https://stackoverflow.com/a/60598827/16654916

func GetUnexportedField(field reflect.Value) interface{} {
    return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

func SetUnexportedField(field reflect.Value, value interface{}) {
    reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).
        Elem().
        Set(reflect.ValueOf(value))
}

func SetUnexportedFieldWithIface(instance interface{}, fieldName string, value interface{}) {
    SetUnexportedField(reflect.Indirect(reflect.ValueOf(instance)).FieldByName(fieldName), value)
}
