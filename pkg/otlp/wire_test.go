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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// unmarshalExportRequest decodes an ExportLogsServiceRequest.
func unmarshalExportRequest(b []byte) ([]*logspb.ResourceLogs, error) {
	var out []*logspb.ResourceLogs
	err := walkFields(b, func(num protowire.Number, typ protowire.Type, v []byte) error {
		if num != requestResourceLogs || typ != protowire.BytesType {
			return nil
		}
		inner, n := protowire.ConsumeBytes(v)
		if n < 0 {
			return errMalformed
		}
		rl := &logspb.ResourceLogs{}
		if err := proto.Unmarshal(inner, rl); err != nil {
			return err
		}
		out = append(out, rl)
		return nil
	})
	return out, err
}

// exportResponse encodes an ExportLogsServiceResponse with a partial
// success.
func exportResponse(rejected int64, message string) []byte {
	var ps []byte
	ps = protowire.AppendTag(ps, partialRejectedRecord, protowire.VarintType)
	ps = protowire.AppendVarint(ps, uint64(rejected))
	ps = protowire.AppendTag(ps, partialErrorMessage, protowire.BytesType)
	ps = protowire.AppendString(ps, message)
	return protowire.AppendBytes(protowire.AppendTag(nil, responsePartial, protowire.BytesType), ps)
}

func goldenResourceLogs() *logspb.ResourceLogs {
	return &logspb.ResourceLogs{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{stringAttr("service.name", "svc")}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "s", Version: "1"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: 1,
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "b"}},
			}},
		}},
	}
}

// The golden bytes are what the generated messages in
// go.opentelemetry.io/proto/otlp/collector/logs/v1 v1.11.0 marshal to:
// ExportLogsServiceRequest{ResourceLogs: {golden, golden}}, and
// ExportLogsServiceResponse{PartialSuccess: {1, "attribute limit exceeded"}}.
const (
	goldenRequest = "0a330a170a150a0c736572766963652e6e616d6512050a0373766312180a060a01731201" +
		"31120e0901000000000000002a030a01620a330a170a150a0c736572766963652e6e616d65" +
		"12050a0373766312180a060a0173120131120e0901000000000000002a030a0162"
	goldenResponse = "0a1c08011218617474726962757465206c696d6974206578636565646564"
)

func TestMarshalExportRequest_MatchesGenerated(t *testing.T) {
	body, err := marshalExportRequest(goldenResourceLogs(), goldenResourceLogs())
	require.NoError(t, err)
	assert.Equal(t, goldenRequest, hex.EncodeToString(body))

	empty, err := marshalExportRequest()
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestMarshalExportRequest_RoundTrip(t *testing.T) {
	in := []*logspb.ResourceLogs{goldenResourceLogs(), {}, goldenResourceLogs()}
	in[2].SchemaUrl = "https://example.com/schema"
	body, err := marshalExportRequest(in...)
	require.NoError(t, err)

	out, err := unmarshalExportRequest(body)
	require.NoError(t, err)
	require.Len(t, out, len(in))
	for i := range in {
		assert.True(t, proto.Equal(in[i], out[i]), "resource_logs[%d]", i)
	}
}

func TestParseExportResponse(t *testing.T) {
	golden, err := hex.DecodeString(goldenResponse)
	require.NoError(t, err)
	assert.Equal(t, golden, exportResponse(1, "attribute limit exceeded"))

	tag := protowire.AppendTag
	varint := func(b []byte, num protowire.Number, v uint64) []byte {
		return protowire.AppendVarint(tag(b, num, protowire.VarintType), v)
	}
	partial := func(inner []byte) []byte {
		return protowire.AppendBytes(tag(nil, responsePartial, protowire.BytesType), inner)
	}

	tests := []struct {
		name    string
		body    []byte
		want    partialSuccess
		wantErr bool
	}{
		{name: "empty body is full success", body: nil},
		{name: "generated encoding", body: golden, want: partialSuccess{1, "attribute limit exceeded"}},
		{
			name: "unknown fields are skipped at both levels",
			body: append(varint(nil, 5, 3), partial(varint(varint(nil, 9, 7), partialRejectedRecord, 4))...),
			want: partialSuccess{rejectedLogRecords: 4},
		},
		{
			name: "a repeated partial_success merges",
			body: append(partial(varint(nil, partialRejectedRecord, 2)),
				partial(protowire.AppendString(tag(nil, partialErrorMessage, protowire.BytesType), "later"))...),
			want: partialSuccess{2, "later"},
		},
		{
			name: "the last scalar wins",
			body: partial(varint(varint(nil, partialRejectedRecord, 2), partialRejectedRecord, 3)),
			want: partialSuccess{rejectedLogRecords: 3},
		},
		{
			name: "partial_success with the wrong wire type is skipped",
			body: varint(nil, responsePartial, 1),
		},
		{
			name: "rejected_log_records with the wrong wire type is skipped",
			body: partial(protowire.AppendString(tag(nil, partialRejectedRecord, protowire.BytesType), "x")),
		},
		{
			name: "error_message with the wrong wire type is skipped",
			body: partial(varint(varint(nil, partialErrorMessage, 1), partialRejectedRecord, 5)),
			want: partialSuccess{rejectedLogRecords: 5},
		},
		{
			name: "negative count",
			body: partial(varint(nil, partialRejectedRecord, uint64(1<<64-1))),
			want: partialSuccess{rejectedLogRecords: -1},
		},
		{
			name: "an unknown group is skipped",
			body: append(tag(varint(tag(nil, 7, protowire.StartGroupType), 1, 9), 7, protowire.EndGroupType), golden...),
			want: partialSuccess{1, "attribute limit exceeded"},
		},
		{
			name: "invalid UTF-8 in error_message keeps the count",
			body: partial(protowire.AppendString(
				tag(varint(nil, partialRejectedRecord, 2), partialErrorMessage, protowire.BytesType), "bad\xffmsg")),
			want: partialSuccess{2, "bad�msg"},
		},
		{name: "an unmatched end-group", body: tag(nil, 7, protowire.EndGroupType), wantErr: true},
		{
			name:    "an unmatched end-group inside partial_success",
			body:    partial(tag(nil, 7, protowire.EndGroupType)),
			wantErr: true,
		},
		{name: "truncated", body: golden[:len(golden)-1], wantErr: true},
		{
			name:    "truncated unknown field",
			body:    append(tag(nil, 5, protowire.BytesType), 3, 'a'),
			wantErr: true,
		},
		{name: "bad tag", body: []byte{0x80}, wantErr: true},
		{
			name:    "a field number above the valid range",
			body:    append(varint(nil, protowire.MaxValidNumber+1, 0), golden...),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExportResponse(tt.body)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// FuzzParseExportResponse checks that no response body panics the decoder,
// and that whatever it decodes re-encodes to the same values.
func FuzzParseExportResponse(f *testing.F) {
	golden, err := hex.DecodeString(goldenResponse)
	require.NoError(f, err)
	f.Add(golden)
	f.Add([]byte{})
	f.Add([]byte{0x80})
	f.Add(exportResponse(-1, "bad\xffmsg"))
	f.Fuzz(func(t *testing.T, body []byte) {
		ps, err := parseExportResponse(body)
		if err != nil {
			return
		}
		again, err := parseExportResponse(exportResponse(ps.rejectedLogRecords, ps.errorMessage))
		require.NoError(t, err)
		assert.Equal(t, ps, again)
	})
}
