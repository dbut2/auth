package html

import (
	"embed"
)

//go:embed *.html
//go:embed */*.html
var Files embed.FS
