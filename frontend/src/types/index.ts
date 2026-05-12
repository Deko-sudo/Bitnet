// Matches EntryListItemSchema (GET /entries)
export interface VaultListItem {
  id: number
  title: string
  url?: string | null
}

// Matches EntryResponseSchema (GET /entries/{id})
export interface VaultEntry {
  id: number
  user_id: number
  title: string
  username?: string | null
  password: string
  url?: string | null
  notes?: string | null
  created_at: string
  updated_at?: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
  user_id: number
  username: string
}

export interface UserResponse {
  id: number
  username: string
  email: string
}

export interface TotpCodeResponse {
  id: number
  issuer: string | null
  account_name: string
  digits: number
  period: number
  current_code: string
  seconds_remaining: number
  vault_entry_id: number | null
  verified: boolean
}

export interface TotpSetupResponse {
  id: number
  otpauth_uri: string
  qr_code_base64: string
}
