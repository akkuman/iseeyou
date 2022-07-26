package util

type HttpStatusCode int

func (c HttpStatusCode) IsServerError() bool {
	return c >= 500 && c < 600
}
