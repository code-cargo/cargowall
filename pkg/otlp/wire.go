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

package otlp

import (
	"errors"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// The two collector messages, ExportLogsServiceRequest and
// ExportLogsServiceResponse, are encoded here by hand. Their generated Go
// package (go.opentelemetry.io/proto/otlp/collector/logs/v1) also holds the
// gRPC service stubs and the grpc-gateway handler, so importing it links
// grpc into the binary for messages that are one and two fields deep. The
// field numbers are from opentelemetry/proto/collector/logs/v1/logs_service.proto.
const (
	requestResourceLogs   protowire.Number = 1 // ExportLogsServiceRequest.resource_logs
	responsePartial       protowire.Number = 1 // ExportLogsServiceResponse.partial_success
	partialRejectedRecord protowire.Number = 1 // ExportLogsPartialSuccess.rejected_log_records
	partialErrorMessage   protowire.Number = 2 // ExportLogsPartialSuccess.error_message
)

var errMalformed = errors.New("malformed protobuf")

// marshalExportRequest encodes an ExportLogsServiceRequest: each
// ResourceLogs as a length-delimited field 1, in order, which is the
// encoding proto.Marshal produces for the generated message.
func marshalExportRequest(resourceLogs ...*logspb.ResourceLogs) ([]byte, error) {
	var out []byte
	for _, rl := range resourceLogs {
		b, err := proto.Marshal(rl)
		if err != nil {
			return nil, err
		}
		out = protowire.AppendTag(out, requestResourceLogs, protowire.BytesType)
		out = protowire.AppendBytes(out, b)
	}
	return out, nil
}

// partialSuccess is ExportLogsPartialSuccess.
type partialSuccess struct {
	rejectedLogRecords int64
	errorMessage       string
}

// parseExportResponse decodes an ExportLogsServiceResponse with proto3
// semantics: unknown fields and fields of an unexpected wire type are
// skipped, a repeated message merges, and the last scalar wins.
func parseExportResponse(b []byte) (partialSuccess, error) {
	var ps partialSuccess
	err := walkFields(b, func(num protowire.Number, typ protowire.Type, v []byte) error {
		if num != responsePartial || typ != protowire.BytesType {
			return nil
		}
		inner, n := protowire.ConsumeBytes(v)
		if n < 0 {
			return errMalformed
		}
		return walkFields(inner, func(num protowire.Number, typ protowire.Type, v []byte) error {
			switch {
			case num == partialRejectedRecord && typ == protowire.VarintType:
				x, n := protowire.ConsumeVarint(v)
				if n < 0 {
					return errMalformed
				}
				ps.rejectedLogRecords = int64(x)
			case num == partialErrorMessage && typ == protowire.BytesType:
				s, n := protowire.ConsumeBytes(v)
				if n < 0 {
					return errMalformed
				}
				ps.errorMessage = string(s)
			}
			return nil
		})
	})
	return ps, err
}

// walkFields calls fn for each field in b with the field's number, wire
// type and the bytes from its value onwards.
func walkFields(b []byte, fn func(protowire.Number, protowire.Type, []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
		if err := fn(num, typ, b); err != nil {
			return err
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
	}
	return nil
}
