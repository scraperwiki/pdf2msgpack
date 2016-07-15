package p2m

import (
	"io"

	"github.com/tinylib/msgp/msgp"
)

//go:generate msgp

//msgp:ignore Reader

// Reader reads pdf2msgpack's output stream.
type Reader struct {
	Version int
	Meta    Meta

	R *msgp.Reader

	currentNumber int
}

// Meta contains metadata about the PDF such as the number of pages.
type Meta struct {
	Pages                       int64
	FileName, Creator, Producer string

	FontInfo *FontInfos
}

// FontInfos is a list of font information.
type FontInfos []FontInfo

// FontInfo contains information about a font in the file.
type FontInfo struct {
	Name                        string
	Type                        string
	Encoding                    string
	Embedded, Subset, ToUnicode bool
}

// Page represents one page of a PDF.
type Page struct {
	Number int // One based.
	Size   Size
	Glyphs []Glyph
	Paths  []Path
}

// Size of the page.
//msgp:tuple Size
type Size struct {
	W, H float64
}

// Glyph represents a single glyph.
//msgp:tuple Glyph
type Glyph struct {
	Rect Rect
	Text string
}

// Rect represents a rectangle.
//msgp:tuple Rect
type Rect struct {
	X1, Y1, X2, Y2 float64
}

// Path represents a path.
//msgp:decode ignore Path
type Path struct {
	Type        PathType
	Data        [][]float64
	StrokeWidth float64
	Color       struct{ R, G, B uint8 }
}

// PathType is one of a set of constants which describes paths.
type PathType uint8

const (
	// PathTypeEoFill ...
	PathTypeEoFill PathType = 10
	// PathTypeStroke ...
	PathTypeStroke = 11
	// PathTypeFill ...
	PathTypeFill = 12
	// PathTypeSetStrokeColor ...
	PathTypeSetStrokeColor = 13
	// PathTypeSetStrokeWidth ...
	PathTypeSetStrokeWidth = 14
	// PathTypeSetFillColor ...
	PathTypeSetFillColor = 15
)

// NewReader reads the header and metadata from a pdf2msgpack stream.
// To read pages, call Next() repeatedly until io.EOF.
func NewReader(r io.Reader) (*Reader, error) {
	reader := &Reader{R: msgp.NewReader(struct{ io.Reader }{r})}

	var err error
	reader.Version, err = reader.R.ReadInt()
	if err != nil {
		return nil, err
	}

	err = reader.Meta.DecodeMsg(reader.R)
	if err != nil {
		return nil, err
	}

	return reader, nil
}

// Next reads the next page into p, or returns io.EOF.
func (r *Reader) Next(p *Page) error {
	r.currentNumber++ // Increment first for one-based counting.
	p.Number = r.currentNumber
	err := p.DecodeMsg(r.R)
	return err
}
