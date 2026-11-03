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

//go:build linux

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// Programs that embed cargowall through this package commonly link the
// OpenTelemetry SDK, which registers the upstream OTLP descriptors. A second
// copy of one under the same proto path panics at init, before main, and
// cargowall's own CI never links the SDK to see it. So every OTLP
// descriptor linked here must be registered by upstream's own Go packages,
// and no collector package (their gRPC stubs link grpc) may be linked at
// all. The Go package checked is the one that registered the file, which a
// copied .pb.go keeping upstream's go_package option can't fake.
func TestOTLPDescriptorsAreUpstream(t *testing.T) {
	var linked int
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		path := fd.Path()
		if !strings.HasPrefix(path, "opentelemetry/") && !strings.HasPrefix(string(fd.Package()), "opentelemetry.") {
			return true
		}
		linked++
		assert.False(t, strings.HasPrefix(path, "opentelemetry/proto/collector/"), "%s is linked", path)
		gp, ok := fd.(interface{ GoPackagePath() string })
		if !assert.True(t, ok, "%s: the registering Go package is not exposed", path) {
			return true
		}
		assert.True(t, strings.HasPrefix(gp.GoPackagePath(), "go.opentelemetry.io/proto/otlp/"),
			"%s is registered by %q", path, gp.GoPackagePath())
		return true
	})
	assert.Positive(t, linked, "the OTLP exporter's descriptors are linked")
}
