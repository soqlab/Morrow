resource "example_tls_policy" "portal" {
  hostname             = "www.cloudflare.com"
  min_tls_version      = "1.2"
  allow_weak_ciphers   = true
  crypto_agility_owner = ""
}

