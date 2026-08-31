//   Copyright 2026 BoxBuild Inc DBA CodeCargo
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package sni

// cursor is a forward-only, bounds-checked reader over a byte slice. Once any
// read runs past the end it latches bad=true and every later read is a no-op,
// so callers can chain reads and check bad once. It never panics.
type cursor struct {
	b   []byte
	off int
	bad bool
}

func (c *cursor) remaining() int {
	if c.bad {
		return 0
	}
	return len(c.b) - c.off
}

// take advances by n and returns the consumed slice, latching bad on overrun.
func (c *cursor) take(n int) []byte {
	if c.bad || n < 0 || c.off+n > len(c.b) {
		c.bad = true
		return nil
	}
	s := c.b[c.off : c.off+n]
	c.off += n
	return s
}

func (c *cursor) skip(n int) { c.take(n) }

func (c *cursor) readU8() uint8 {
	s := c.take(1)
	if c.bad {
		return 0
	}
	return s[0]
}

func (c *cursor) readU16() uint16 {
	s := c.take(2)
	if c.bad {
		return 0
	}
	return uint16(s[0])<<8 | uint16(s[1])
}

// readVec8 reads a u8-length-prefixed vector and returns its body.
func (c *cursor) readVec8() []byte {
	n := int(c.readU8())
	return c.take(n)
}

// readVec16 reads a u16-length-prefixed vector and returns its body.
func (c *cursor) readVec16() []byte {
	n := int(c.readU16())
	return c.take(n)
}

func (c *cursor) skipVec8() { c.readVec8() }

func (c *cursor) skipVec16() { c.readVec16() }
