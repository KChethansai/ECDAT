# Demo cloud crypto config (fictional identifiers, no credentials).
resource "aws_kms_key" "demo" {
  description = "demo key"
}

resource "azurerm_key_vault" "demo" {
  name = "demo-vault"
}

resource "google_kms_crypto_key" "demo" {
  name = "demo-key"
}
