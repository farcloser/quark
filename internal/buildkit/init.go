/*
   Copyright Farcloser.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package buildkit

import (
	"log/slog"
	"os"
)

// Note: buildkit internally uses init to set up colors. Overriding the env var must happen before the module is hit.
// This currently does not matter for shelling out, but will once we integrate as a library.
func init() { //nolint:gochecknoinits
	colors := colors()

	err := os.Setenv("BUILDKIT_COLORS", colors)
	if err != nil {
		slog.Error("Failed to set environment variable BUILDKIT_COLORS. Custom colors will not be used.", "error", err)
	}
}
