use super::*;

#[cfg(test)]
mod tests_usize {
    use super::*;

    #[test_case]
    pub(super) fn test_usize_basic() {
        let mut xa = XArrayUsize::new();

        assert!(xa.is_empty());

        xa.store(0, 42);
        xa.store(10, 100);

        assert_eq!(xa.len(), 2);
        assert_eq!(xa.load(0), Some(42));
        assert_eq!(xa.load(10), Some(100));
        assert_eq!(xa.load(5), None);

        assert_eq!(xa.erase(0), Some(42));
        assert_eq!(xa.load(0), None);
        assert_eq!(xa.len(), 1);
    }

    #[test_case]
    pub(super) fn test_usize_marks() {
        let mut xa = XArrayUsize::new();

        xa.store(0, 100);

        assert!(!xa.has_mark(0, XA_MARK_0));
        xa.set_mark(0, XA_MARK_0);
        assert!(xa.has_mark(0, XA_MARK_0));

        xa.clear_mark(0, XA_MARK_0);
        assert!(!xa.has_mark(0, XA_MARK_0));
    }

    #[test_case]
    pub(super) fn test_usize_zero_value() {
        let mut xa = XArrayUsize::new();

        // 0 も正しく格納できる
        xa.store(0, 0);
        assert_eq!(xa.load(0), Some(0));
        assert_eq!(xa.len(), 1);
    }
}
