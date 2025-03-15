package utils

import "strings"

func ParseArgs(raw string) []string {
	raw = strings.TrimSpace(raw)

	var spec []string
	builder := strings.Builder{}
	insideQuotes := false
	for _, c := range raw {
		if c == ' ' && !insideQuotes {
			if builder.Len() > 0 {
				spec = append(spec, builder.String())
				builder.Reset()
			}
			continue
		}
		if c == '"' {
			insideQuotes = !insideQuotes
			continue
		}
		builder.WriteRune(c)
	}
	if builder.Len() > 0 {
		spec = append(spec, builder.String())
	}
	// invalid
	if insideQuotes {
		return nil
	}

	return spec
}

func ExtractComment(specRaw string) string {
	// parse raw iptables string into args
	spec := ParseArgs(specRaw)

	commentIdx := -1
	for i, arg := range spec {
		if arg == "--comment" && i+1 < len(spec) {
			commentIdx = i + 1
			break
		}
	}
	if commentIdx == -1 {
		return ""
	}
	return spec[commentIdx]
}
