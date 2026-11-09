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

// Bridge-device discovery for Options.OnBridge and OnBridgeGone: which
// host device each bridge-driver network forwards its containers' traffic
// through, from the session's network list, network creates and
// destroys.

package containers

// Network options that name a bridge network's host device. Docker sets
// bridgeNameOption on the default network (docker0, or what --bridge
// named), and on a user-defined network created with it; any other
// bridge network's device is br- and the network id's first 12
// characters.
const (
	bridgeNameOption    = "com.docker.network.bridge.name"
	defaultBridgeOption = "com.docker.network.bridge.default_bridge"
)

// bridgeDevice names a bridge-driver network's host device.
func bridgeDevice(nw networkInspect) string {
	if name := nw.Options[bridgeNameOption]; name != "" {
		return name
	}
	if nw.Options[defaultBridgeOption] == "true" {
		return "docker0"
	}
	if nw.ID == "" {
		return ""
	}
	return "br-" + shortID(nw.ID)
}

// bridgeUp records a bridge-driver network's device under the network's
// id and hands it to Options.OnBridge.
func (t *Tracker) bridgeUp(nw networkInspect) {
	if t.opts.OnBridge == nil {
		return
	}
	dev := bridgeDevice(nw)
	if dev == "" {
		return
	}
	t.mu.Lock()
	t.bridges[nw.ID] = dev
	t.mu.Unlock()
	t.opts.OnBridge(dev)
}

// bridgeGone hands a destroyed network's device, if it was a bridge seen
// up, to Options.OnBridgeGone.
func (t *Tracker) bridgeGone(networkID string) {
	if t.opts.OnBridge == nil {
		return
	}
	t.mu.Lock()
	dev, ok := t.bridges[networkID]
	delete(t.bridges, networkID)
	t.mu.Unlock()
	if ok && t.opts.OnBridgeGone != nil {
		t.opts.OnBridgeGone(dev)
	}
}

// bridgesListed takes a session's network list as the whole set of
// bridges: one seen up before that is not in it was destroyed in a stream
// gap, and its device, unless a listed network now uses it, goes to
// Options.OnBridgeGone. Each listed bridge then goes to bridgeUp: the
// receiver tells one it has already from one recreated behind the same
// name.
func (t *Tracker) bridgesListed(nets []networkInspect) {
	if t.opts.OnBridge == nil {
		return
	}
	listed := make(map[string]bool)
	for _, nw := range nets {
		if nw.Driver == "bridge" {
			listed[bridgeDevice(nw)] = true
		}
	}
	t.mu.Lock()
	var gone []string
	for id, dev := range t.bridges {
		if !listed[dev] {
			gone = append(gone, dev)
		}
		delete(t.bridges, id)
	}
	t.mu.Unlock()
	if t.opts.OnBridgeGone != nil {
		for _, dev := range gone {
			t.opts.OnBridgeGone(dev)
		}
	}
	for _, nw := range nets {
		if nw.Driver == "bridge" {
			t.bridgeUp(nw)
		}
	}
}
