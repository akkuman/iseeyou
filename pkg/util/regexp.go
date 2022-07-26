package util

import "regexp"

// ReSubMatchMap 提取group name, n 参数请参见 regexp.FindAll 中的n参数
// ref: https://stackoverflow.com/questions/20750843/using-named-matches-from-go-regex
func ReSubMatchMap(r *regexp.Regexp, s string, n int) (subMatchMaps []map[string]string) {
    matches := r.FindAllStringSubmatch(s, n)
	for _, match := range matches {
		subMatchMap := make(map[string]string)
		for i, name := range r.SubexpNames() {
			if i != 0 {
				subMatchMap[name] = match[i]
			}
		}
		subMatchMaps = append(subMatchMaps, subMatchMap)
	}
    return
}
