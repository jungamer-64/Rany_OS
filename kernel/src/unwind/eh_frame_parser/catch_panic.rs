use super::*;


/// パニックを捕捉して実行
/// 
/// no_std環境での `std::panic::catch_unwind` 相当の機能を提供する。
/// 
/// # 設計書 8.2: ドメイン境界でのパニック捕捉
/// 
/// プロキシ呼び出し時にこの関数を使用することで、ドメインのパニックを
/// 捕捉し、呼び出し元ドメインに `Result::Err` として伝播させる。
/// 
/// # 使用例
/// ```
/// let result = catch_panic(|| {
///     // パニックする可能性のあるコード
///     risky_operation()
/// });
/// 
/// match result {
///     Ok(value) => println!("Success: {:?}", value),
///     Err(payload) => println!("Caught panic: {}", payload),
/// }
/// ```
/// 
/// # 制限事項
/// - 真のスタックアンワインドは行われない
/// - パニックしたコードのDropトレイトは呼ばれない
/// - パニックハンドラがこの機構と統合されている必要がある
/// 
/// # 安全性
/// この関数自体はsafeだが、パニック時のリソースリークに注意が必要。
/// 設計書 8.1 のリソース回収機構と組み合わせて使用すること。
pub fn catch_panic<F, T>(f: F) -> CatchResult<T>
where
    F: FnOnce() -> T,
{
    // パニック捕捉を有効化
    let was_active = PANIC_CATCH_ACTIVE.swap(true, Ordering::SeqCst);
    
    // 前の捕捉状態をクリア
    PANIC_CAUGHT.store(false, Ordering::SeqCst);
    
    // 関数を実行
    let result = f();
    
    // パニック捕捉を復元
    PANIC_CATCH_ACTIVE.store(was_active, Ordering::SeqCst);
    
    // パニックが捕捉されたかチェック
    if let Some(payload) = take_caught_panic() {
        return Err(payload);
    }
    
    Ok(result)
}

/// パニック捕捉付きで関数を実行し、AssertUnwindSafe相当の保証を提供
/// 
/// `catch_panic` との違い:
/// - 明示的にUnwindSafeでないクロージャを受け入れる
/// - 「このコードはパニック後も安全」という意図を示す
pub fn catch_panic_unwind_safe<F, T>(f: F) -> CatchResult<T>
where
    F: FnOnce() -> T,
{
    catch_panic(f)
}

/// パニック捕捉スコープガード
/// 
/// RAII パターンでパニック捕捉の有効/無効を管理する。
/// Drop時に自動的に以前の状態に復元される。
pub struct PanicCatchGuard {
    was_active: bool,
}

impl PanicCatchGuard {
    /// 新しいパニック捕捉スコープを開始
    pub fn new() -> Self {
        let was_active = PANIC_CATCH_ACTIVE.swap(true, Ordering::SeqCst);
        PANIC_CAUGHT.store(false, Ordering::SeqCst);
        Self { was_active }
    }
    
    /// パニックが捕捉されたかチェック
    pub fn caught_panic(&self) -> bool {
        PANIC_CAUGHT.load(Ordering::SeqCst)
    }
    
    /// 捕捉されたパニック情報を取得
    pub fn take_panic(&self) -> Option<PanicPayload> {
        take_caught_panic()
    }
}

impl Drop for PanicCatchGuard {
    fn drop(&mut self) {
        PANIC_CATCH_ACTIVE.store(self.was_active, Ordering::SeqCst);
    }
}

impl Default for PanicCatchGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;

