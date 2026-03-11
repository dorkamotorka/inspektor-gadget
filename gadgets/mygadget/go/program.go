package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	api.Info("kubelet_tls gadget has initialized!")
	return 0
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	api.Info("kubelet_tls gadget has started!")
	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	api.Info("kubelet_tls gadget has stopped!")
	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}
