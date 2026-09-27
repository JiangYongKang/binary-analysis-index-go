package scan_test

import "os"

func readFileOS(p string) ([]byte, error)  { return os.ReadFile(p) }
func writeFileOS(p string, b []byte) error { return os.WriteFile(p, b, 0o644) }
