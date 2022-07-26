package util

type StringSet map[string]struct{}

func NewStringSet() StringSet {
	s := make(StringSet)
	return s
}

func (s StringSet) GetList() []string {
	ss := make([]string, len(s))
	i := 0
	for k := range s {
		ss[i] = k
		i += 1
	}
	return ss
}

func (s StringSet) Add(k string) {
	s[k] = struct{}{}
}

// MergeStringList 合并多个 string list
func MergeStringList(lists ...[]string) []string {
	s := NewStringSet()
	for _, l := range lists {
		for _, element := range l {
			s.Add(element)
		}
	}
	return s.GetList()
}
