module go-fdo-quick-di

go 1.25.0

require (
	github.com/fido-device-onboard/go-fdo v0.0.0
	github.com/fido-device-onboard/go-fdo/cred v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/fido-device-onboard/go-fdo/tpm v0.0.0-00010101000000-000000000000 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/go-tpm-tools v0.4.7 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/fido-device-onboard/go-fdo => ./go-fdo

replace github.com/fido-device-onboard/go-fdo/cred => ./go-fdo/cred

replace github.com/fido-device-onboard/go-fdo/tpm => ./go-fdo/tpm
