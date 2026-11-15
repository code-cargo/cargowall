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

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
)

// A local config file is read strictly. Unlike a CodeCargo policy, whose
// schema the API enforces, it is hand-written, and json.Unmarshal reads it
// loosely: an unknown key is ignored, a key in another case still fills the
// field, a repeated key merges into the field, and a port entry whose
// protocol cargowall doesn't know is skipped, which leaves its rule on every
// port. So a file must spell what cargowall reads, exactly, or not load at
// all: a file that loads is never wider than it reads.

// decodeLocalConfig decodes a local config file: a JSON object whose keys,
// at every level, are exactly FirewallConfig's, each given once
// (checkExactKeys, which leaves no unknown key for the decoder to ignore),
// whose default action is allow or deny when given, and whose rules resolve
// as written (validateLocalRules).
func decodeLocalConfig(data []byte) (*FirewallConfig, error) {
	if err := checkExactKeys(data, reflect.TypeFor[FirewallConfig]()); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var cfg FirewallConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("parse config: data after the top-level object")
	}
	switch cfg.DefaultAction {
	case "", ActionAllow, ActionDeny:
	default:
		return nil, fmt.Errorf("defaultAction %q must be allow or deny (deny when left out)", cfg.DefaultAction)
	}
	if err := validateLocalRules(cfg.Rules, "rules", false); err != nil {
		return nil, err
	}
	for i := range cfg.Steps {
		if err := validateLocalRules(cfg.Steps[i].Rules, fmt.Sprintf("steps[%d].rules", i), true); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

// checkExactKeys walks data's tokens against t, the type it decodes into:
// the top level must be an object, and every object a struct decodes from
// may hold only that struct's JSON keys, in their exact case, each once.
func checkExactKeys(data []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("parse config: the top level must be a JSON object")
	}
	return checkObject(dec, t, "the config")
}

// checkObject checks the rest of an object, its '{' read, against struct t.
func checkObject(dec *json.Decoder, t reflect.Type, where string) error {
	fields := jsonFields(t)
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return fmt.Errorf("parse config: %s repeats the key %q", where, key)
		}
		seen[key] = true
		ft, ok := fields[key]
		if !ok {
			return fmt.Errorf("parse config: %s has a key cargowall doesn't read: %q (keys are matched exactly)", where, key)
		}
		if err := checkValue(dec, ft, where+"."+key); err != nil {
			return err
		}
	}
	_, err := dec.Token() // the closing '}'
	return err
}

// checkValue checks the next value against t: an object decoding into a
// struct, or an array of them, is checked in turn; anything else is left to
// the decoder, which refuses a value of the wrong type.
func checkValue(dec *json.Decoder, t reflect.Type, where string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case d == '{' && t.Kind() == reflect.Struct:
		return checkObject(dec, t, where)
	case d == '[' && t.Kind() == reflect.Slice:
		for i := 0; dec.More(); i++ {
			if err := checkValue(dec, t.Elem(), fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
		_, err := dec.Token() // the closing ']'
		return err
	}
	return skipValue(dec)
}

// skipValue reads past the rest of a value whose opening '{' or '[' has
// been read.
func skipValue(dec *json.Decoder) error {
	for depth := 1; depth > 0; {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
		if dd, ok := tok.(json.Delim); ok {
			if dd == '{' || dd == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// jsonFields maps each of struct t's JSON keys to its field's type.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" || !f.IsExported() {
			continue
		}
		fields[name] = f.Type
	}
	return fields
}

// validateLocalRules refuses, in a local file, each rule shape the loaders
// would otherwise accept and resolve would drop, or that would end up on
// more ports than it spells: a type other than hostname or cidr, an empty
// value, a CIDR that doesn't parse, a hostname pattern that doesn't
// compile, a job rule whose action isn't allow or deny, an autoAddedType
// (cargowall sets it), an empty ports list, or a port entry whose protocol
// isn't exactly one cargowall knows. A step rule's action is
// compileStepRules's to check.
func validateLocalRules(rules []Rule, where string, step bool) error {
	for i, r := range rules {
		at := fmt.Sprintf("%s[%d]", where, i)
		switch r.Type {
		case RuleTypeHostname:
			if r.Value == "" {
				return fmt.Errorf("%s: a hostname rule needs a value", at)
			}
			if isHostnamePattern(r.Value) {
				if _, err := compileHostnamePattern(strings.ToLower(r.Value)); err != nil {
					return fmt.Errorf("%s: invalid hostname pattern %q: %w", at, r.Value, err)
				}
			}
		case RuleTypeCIDR:
			if _, _, err := net.ParseCIDR(r.Value); err != nil && net.ParseIP(r.Value) == nil {
				return fmt.Errorf("%s: %q is not a CIDR or an IP address", at, r.Value)
			}
		default:
			return fmt.Errorf("%s: unknown rule type %q (hostname or cidr)", at, r.Type)
		}
		if !step && r.Action != ActionAllow && r.Action != ActionDeny {
			return fmt.Errorf("%s: action %q must be allow or deny", at, r.Action)
		}
		if r.AutoAddedType != AutoAddedTypeNone {
			return fmt.Errorf("%s: autoAddedType is set by cargowall, not by a config file", at)
		}
		if r.Ports != nil && len(r.Ports) == 0 {
			return fmt.Errorf("%s: ports is empty; omit ports for every port", at)
		}
		for j, p := range r.Ports {
			switch p.Protocol {
			case ProtocolAll, ProtocolTCP, ProtocolUDP, ProtocolICMP:
			default:
				return fmt.Errorf("%s.ports[%d]: protocol %q must be all, tcp, udp or icmp", at, j, p.Protocol)
			}
		}
	}
	return nil
}
