module github.com/farcloser/quark

go 1.24.0

// Force old monolithic genproto to be replaced by split packages
replace google.golang.org/genproto => google.golang.org/genproto v0.0.0-20250218202821-56aae31c358a

require (
	github.com/carapace-sh/carapace-shlex v1.1.1
	github.com/distribution/reference v0.6.0
	github.com/google/go-containerregistry v0.20.6
	github.com/joho/godotenv v1.5.1
	github.com/kevinburke/ssh_config v1.4.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/pkg/sftp v1.13.9
	github.com/rs/zerolog v1.34.0
	github.com/urfave/cli/v3 v3.5.0
	golang.org/x/crypto v0.43.0
	gotest.tools/v3 v3.0.3
)

require (
	github.com/containerd/stargz-snapshotter/estargz v0.16.3 // indirect
	github.com/docker/cli v28.4.0+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/vbatts/tar-split v0.12.1 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
)
