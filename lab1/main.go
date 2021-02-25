package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	studentId := []byte("20173700")
	hash := sha256.Sum256(studentId)
	has2x := sha256.Sum256(hash[:])
	has3x := sha256.Sum256(has2x[:])
	has4x := sha256.Sum256(has3x[:])
	has5x := sha256.Sum256(has4x[:])
	fmt.Printf("%x", has3x[:])
	fmt.Println("\n")
	fmt.Printf("%x", has5x[:])
}
