package cmd

import "os"

// openFile opens a file for reading. Caller must close.
func openFile(path string) (*os.File, error) {
	return os.Open(path)
}
