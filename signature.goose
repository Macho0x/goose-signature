// Package entry. Declaring `import signature from "../signature";` loads this
// file and nothing else. Load a module with `import signature.eip191;`.
// `goose tests/self_check.goose` runs every published vector.

import crypto from "../crypto";

fn ::main() {
    print("goose tests/self_check.goose");
}
