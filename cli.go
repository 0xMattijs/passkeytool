package main

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
