package main

import (
	"fmt"
	"github.com/0xrawsec/golang-etw/etw"
)

func main() {
	// check what constructors exist
	fmt.Printf("NewRealTimeConsumer constructor exists and has type: %T\n", etw.NewRealTimeConsumer)
}
