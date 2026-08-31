// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - API Key authentication
// ============================================================================
//
// API-key per client programmatici (in particolare il server MCP). Vivono in
// `user_api_keys`: per-utente, revocabili, con scope 'read'/'write'. Una chiave
// "impersona" il proprio utente — le credenziali derivate portano lo STESSO
// user_id/role, quindi l'RBAC esistente si applica invariato.
//
// Formato: "sk_<48 alfanumerici>". In storage si conserva solo lo SHA-256
// dell'intera stringa (mai la chiave in chiaro). Portato da SentinelCore e
// adattato agli id interi di CyberSheppard.
//
// Le query sono RUNTIME (non il macro `query!`) di proposito: non richiedono la
// cache sqlx offline, così il build resta verde senza `cargo sqlx prepare`.

use rand::distr::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::middleware::auth::AuthUser;

/// Numero di caratteri casuali dopo il prefisso "sk_".
const KEY_RANDOM_LEN: usize = 48;

/// SHA-256 (hex) dell'intera chiave in chiaro ("sk_..."). Usato sia alla
/// creazione che alla validazione: DEVONO combaciare.
pub fn hash_api_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Genera una nuova API-key. Ritorna `(chiave_in_chiaro, prefisso_display)`.
/// La chiave in chiaro va mostrata all'utente UNA sola volta; in DB si salva
/// solo `hash_api_key(&raw)` e il prefisso.
pub fn generate_api_key() -> (String, String) {
    let suffix: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(KEY_RANDOM_LEN)
        .map(char::from)
        .collect();
    let raw = format!("sk_{suffix}");
    let prefix = raw.chars().take(7).collect(); // "sk_" + 4 char
    (raw, prefix)
}

/// Valida una API-key in chiaro. Se esiste, non è scaduta e appartiene a un
/// utente attivo, restituisce l'`AuthUser` di quell'utente (con
/// `mcp_key_scope` valorizzato) e aggiorna `last_used_at` (best-effort).
/// Ritorna `None` per chiave assente/scaduta/utente disattivato.
pub async fn authenticate_api_key(pool: &PgPool, raw_key: &str) -> Option<AuthUser> {
    // Prefiltro: le nostre chiavi iniziano con "sk_". Evita un lookup inutile
    // quando il token è in realtà un JWT (che non inizia mai con "sk_").
    if !raw_key.starts_with("sk_") {
        return None;
    }

    let key_hash = hash_api_key(raw_key);

    let row: (i64, i32, String, String, String) = sqlx::query_as(
        r#"
        SELECT k.id, u.id, u.username, u.role, k.scope
        FROM user_api_keys k
        JOIN users u ON u.id = k.user_id AND u.is_active = true
        WHERE k.key_hash = $1
          AND (k.expires_at IS NULL OR k.expires_at > NOW())
        "#,
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await
    .ok()??;

    let (key_id, user_id, username, role, scope) = row;

    // Best-effort: un fallimento qui non deve negare l'autenticazione.
    let _ = sqlx::query("UPDATE user_api_keys SET last_used_at = NOW() WHERE id = $1")
        .bind(key_id)
        .execute(pool)
        .await;

    Some(AuthUser {
        user_id,
        username,
        role,
        mcp_key_scope: Some(scope),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_sha256_length() {
        let a = hash_api_key("sk_abc123");
        let b = hash_api_key("sk_abc123");
        assert_eq!(a, b, "stesso input ⇒ stesso hash");
        assert_eq!(a.len(), 64, "SHA-256 in hex = 64 caratteri");
    }

    #[test]
    fn hash_differs_for_different_keys() {
        assert_ne!(hash_api_key("sk_one"), hash_api_key("sk_two"));
    }

    #[test]
    fn generated_key_has_expected_shape() {
        let (raw, prefix) = generate_api_key();
        assert!(raw.starts_with("sk_"));
        assert_eq!(raw.len(), 3 + KEY_RANDOM_LEN);
        assert_eq!(prefix.len(), 7);
        assert!(raw.starts_with(&prefix));
    }
}
