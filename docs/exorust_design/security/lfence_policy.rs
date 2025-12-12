//! LFENCE挿入ポリシー
//!
//! 設計書セクション 9.2.2.2 参照

/// LFENCE挿入基準（厳格に制限）
/// 
/// MPKを第一級防御とすることで、LFENCEの使用は最小限に抑える
/// 以下の条件を満たす箇所にのみLFENCEを挿入:
/// 1. MPKで保護されていない機密データへのアクセス
/// 2. キャッシュタイミング攻撃が致命的な箇所（暗号処理等）
/// 3. 外部入力に基づく分岐の直後（かつMPK保護外）

/// 暗号鍵のロード（MPK + LFENCE の二重防御）
pub fn load_crypto_key(key_id: u32) -> Result<CryptoKey, KeyError> {
    // MPKで保護されたCryptoSecrets領域からのみ読み取り可能
    // ただし、タイミング攻撃対策としてLFENCEも挿入
    unsafe { core::arch::x86_64::_mm_lfence() };
    
    let key = CRYPTO_KEY_STORE.get(key_id)?;
    
    // ロード完了を保証
    unsafe { core::arch::x86_64::_mm_lfence() };
    
    Ok(key)
}

/// コンパイラプラグインの判定ロジック
pub fn should_insert_lfence(context: &AnalysisContext) -> bool {
    // MPKで十分に保護されている場合はLFENCE不要
    if context.is_mpk_protected() && !context.is_crypto_critical() {
        return false;
    }
    
    // 以下の条件でのみ挿入
    context.is_crypto_operation() ||
    context.accesses_unprotected_secret() ||
    context.is_timing_critical()
}

// 以下はプレースホルダー
pub struct CryptoKey([u8; 32]);
pub enum KeyError { NotFound }

struct CryptoKeyStore;
impl CryptoKeyStore {
    fn get(&self, _id: u32) -> Result<CryptoKey, KeyError> {
        Err(KeyError::NotFound)
    }
}
static CRYPTO_KEY_STORE: CryptoKeyStore = CryptoKeyStore;

pub struct AnalysisContext;
impl AnalysisContext {
    fn is_mpk_protected(&self) -> bool { false }
    fn is_crypto_critical(&self) -> bool { false }
    fn is_crypto_operation(&self) -> bool { false }
    fn accesses_unprotected_secret(&self) -> bool { false }
    fn is_timing_critical(&self) -> bool { false }
}
