package main

// Variables referenced by legacy serve preflight (onboard package is legacy-tagged).
var (
	onboardPolicyPath          string
	onboardSlackWebhook        string
	onboardPagerDutyRoutingKey string
	onboardIDPProvider         string
	onboardSPIFFESocket        string
	onboardSPIFFEID            string
	onboardVaultAddr           string
	onboardAWSRegion           string
	onboardGCPProject          string
	onboardAzureVaultURL       string
	onboardInteractive         bool
	onboardCredentialProfile   string
	onboardCredentialBackend   string
	onboardStrict              bool
	onboardJSON                bool
)
