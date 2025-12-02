// ============================================================================
// src/task/per_core_executor.rs - Per-Core Executor
// 設計書 4.3: Per-Core Executorとワークスティーリング
// 
// 各CPUコアに専用のエグゼキュータを持ち、ロック競合なしでタスクを実行。
// コア間の負荷分散はWork Stealingで行う。
// ============================================================================
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use spin::Mutex;

// ============================================================================
// Generic Work-Stealing Queue (for Per-Core Executor)
// ============================================================================

/// ジェネリックなワークスティーリングキュー
/// 
/// Per-Core Executor 専用の実装。
/// Mutex で保護されたVecDequeを使用した簡易実装。
pub struct WorkStealingQueue<T> {
    /// 内部キュー（Mutex保護）
    inner: Mutex<VecDeque<T>>,
}

impl<T> WorkStealingQueue<T> {
    /// 新しいキューを作成
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(256)),
        }
    }
    
    /// アイテムをプッシュ
    pub fn push(&self, item: T) {
        self.inner.lock().push_back(item);
    }
    
    /// アイテムをポップ（LIFO: ローカル実行用）
    pub fn pop(&self) -> Option<T> {
        self.inner.lock().pop_back()
    }
    
    /// アイテムをスチール（FIFO: 他コアからの取得用）
    pub fn steal(&self) -> Option<T> {
        self.inner.lock().pop_front()
    }
    
    /// キューの長さ
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
    
    /// キューが空かどうか
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl<T> Default for WorkStealingQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Task Types
// ============================================================================

/// タスクID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(u64);

impl TaskId {
    /// 新しいタスクIDを生成
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
    
    /// IDの値を取得
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

/// タスクの優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Priority {
    /// リアルタイム優先度
    Realtime = 0,
    /// 高優先度
    High = 1,
    /// 通常優先度
    Normal = 2,
    /// 低優先度（バックグラウンド）
    Low = 3,
    /// アイドル優先度
    Idle = 4,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// タスクの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// 実行可能
    Ready,
    /// 実行中
    Running,
    /// ブロック中
    Blocked,
    /// 完了
    Completed,
}

/// タスクのメタデータ
#[derive(Debug)]
pub struct TaskMetadata {
    /// タスクID
    pub id: TaskId,
    /// 優先度
    pub priority: Priority,
    /// 所属ドメインID
    pub domain_id: Option<u64>,
    /// 作成時刻（ticks）
    pub created_at: u64,
    /// 最後に実行された時刻
    pub last_run_at: AtomicU64,
    /// 総実行時間（cycles）
    pub total_run_time: AtomicU64,
    /// スケジュール回数
    pub schedule_count: AtomicU64,
}

impl TaskMetadata {
    /// 新しいメタデータを作成
    pub fn new(priority: Priority, domain_id: Option<u64>) -> Self {
        Self {
            id: TaskId::new(),
            priority,
            domain_id,
            created_at: read_tsc(),
            last_run_at: AtomicU64::new(0),
            total_run_time: AtomicU64::new(0),
            schedule_count: AtomicU64::new(0),
        }
    }
}

/// タスク構造体
pub struct Task {
    /// タスクのメタデータ
    pub metadata: TaskMetadata,
    /// Futureの実体
    future: UnsafeCell<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    /// タスクの状態
    state: AtomicUsize,
}

// Safety: Task内のUnsafeCellは単一のエグゼキュータスレッドからのみアクセスされる
unsafe impl Send for Task {}
unsafe impl Sync for Task {}

impl Task {
    /// 新しいタスクを作成
    pub fn new<F>(future: F, priority: Priority, domain_id: Option<u64>) -> Arc<Self>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Arc::new(Self {
            metadata: TaskMetadata::new(priority, domain_id),
            future: UnsafeCell::new(Box::pin(future)),
            state: AtomicUsize::new(TaskState::Ready as usize),
        })
    }
    
    /// タスクの状態を取得
    pub fn state(&self) -> TaskState {
        match self.state.load(Ordering::Acquire) {
            0 => TaskState::Ready,
            1 => TaskState::Running,
            2 => TaskState::Blocked,
            _ => TaskState::Completed,
        }
    }
    
    /// タスクの状態を設定
    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as usize, Ordering::Release);
    }
    
    /// タスクをpollする
    /// 
    /// # Safety
    /// 同一のTaskに対して複数のスレッドから同時にpollしてはいけない
    unsafe fn poll(&self, waker: &Waker) -> Poll<()> {
        let future = &mut *self.future.get();
        let mut cx = Context::from_waker(waker);
        future.as_mut().poll(&mut cx)
    }
}

// ============================================================================
// Per-Core Executor
// ============================================================================

/// Per-Core エグゼキュータ
/// 
/// 各CPUコアが専用のエグゼキュータを持つ。
/// ローカルキューへのアクセスはロック不要。
pub struct PerCoreExecutor {
    /// コアID
    core_id: u32,
    /// ローカルの実行キュー
    local_queue: WorkStealingQueue<Arc<Task>>,
    /// 高優先度キュー
    high_priority_queue: Mutex<VecDeque<Arc<Task>>>,
    /// 現在実行中のタスク数
    running_count: AtomicUsize,
    /// 統計: 実行したタスク数
    tasks_executed: AtomicU64,
    /// 統計: スチールしたタスク数
    tasks_stolen: AtomicU64,
    /// 統計: スチールされたタスク数
    tasks_stolen_from: AtomicU64,
    /// シャットダウンフラグ
    shutdown: AtomicBool,
}

impl PerCoreExecutor {
    /// 新しいエグゼキュータを作成
    pub fn new(core_id: u32) -> Self {
        Self {
            core_id,
            local_queue: WorkStealingQueue::new(),
            high_priority_queue: Mutex::new(VecDeque::new()),
            running_count: AtomicUsize::new(0),
            tasks_executed: AtomicU64::new(0),
            tasks_stolen: AtomicU64::new(0),
            tasks_stolen_from: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        }
    }
    
    /// コアIDを取得
    pub fn core_id(&self) -> u32 {
        self.core_id
    }
    
    /// タスクをローカルキューに追加
    pub fn spawn(&self, task: Arc<Task>) {
        if task.metadata.priority <= Priority::High {
            // 高優先度タスクは専用キューへ
            self.high_priority_queue.lock().push_back(task);
        } else {
            // 通常タスクはワークスティーリングキューへ
            self.local_queue.push(task);
        }
    }
    
    /// タスクをスケジュール（Wakerから呼ばれる）
    pub fn schedule(&self, task: Arc<Task>) {
        task.set_state(TaskState::Ready);
        self.spawn(task);
    }
    
    /// 次のタスクを取得
    fn next_task(&self) -> Option<Arc<Task>> {
        // 1. 高優先度キューを最初にチェック
        if let Some(task) = self.high_priority_queue.lock().pop_front() {
            return Some(task);
        }
        
        // 2. ローカルキューからpop
        self.local_queue.pop()
    }
    
    /// 他のエグゼキュータからタスクをスチール
    pub fn steal_from(&self, other: &PerCoreExecutor) -> Option<Arc<Task>> {
        if let Some(task) = other.local_queue.steal() {
            self.tasks_stolen.fetch_add(1, Ordering::Relaxed);
            other.tasks_stolen_from.fetch_add(1, Ordering::Relaxed);
            Some(task)
        } else {
            None
        }
    }
    
    /// 複数のエグゼキュータからタスクをスチール
    pub fn steal_batch_from(&self, other: &PerCoreExecutor, max_count: usize) -> usize {
        let mut stolen = 0;
        for _ in 0..max_count {
            if let Some(task) = other.local_queue.steal() {
                self.local_queue.push(task);
                stolen += 1;
            } else {
                break;
            }
        }
        
        if stolen > 0 {
            self.tasks_stolen.fetch_add(stolen as u64, Ordering::Relaxed);
            other.tasks_stolen_from.fetch_add(stolen as u64, Ordering::Relaxed);
        }
        
        stolen
    }
    
    /// エグゼキュータのメインループ（1イテレーション）
    pub fn run_once(&self) -> bool {
        if self.shutdown.load(Ordering::Acquire) {
            return false;
        }
        
        if let Some(task) = self.next_task() {
            self.run_task(&task);
            true
        } else {
            false
        }
    }
    
    /// 単一のタスクを実行
    fn run_task(&self, task: &Arc<Task>) {
        self.running_count.fetch_add(1, Ordering::Relaxed);
        task.set_state(TaskState::Running);
        
        let start_cycles = read_tsc();
        task.metadata.last_run_at.store(start_cycles, Ordering::Relaxed);
        task.metadata.schedule_count.fetch_add(1, Ordering::Relaxed);
        
        // Wakerを作成
        let waker = task_waker(task.clone(), self.core_id);
        
        // タスクをpoll
        let poll_result = unsafe { task.poll(&waker) };
        
        let end_cycles = read_tsc();
        let elapsed = end_cycles.saturating_sub(start_cycles);
        task.metadata.total_run_time.fetch_add(elapsed, Ordering::Relaxed);
        
        match poll_result {
            Poll::Ready(()) => {
                // タスク完了
                task.set_state(TaskState::Completed);
            }
            Poll::Pending => {
                // タスクはWakerによって再スケジュールされる
                task.set_state(TaskState::Blocked);
            }
        }
        
        self.running_count.fetch_sub(1, Ordering::Relaxed);
        self.tasks_executed.fetch_add(1, Ordering::Relaxed);
    }
    
    /// エグゼキュータをシャットダウン
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
    
    /// キューの長さを取得
    pub fn queue_length(&self) -> usize {
        self.local_queue.len() + self.high_priority_queue.lock().len()
    }
    
    /// 統計を取得
    pub fn stats(&self) -> ExecutorStats {
        ExecutorStats {
            core_id: self.core_id,
            tasks_executed: self.tasks_executed.load(Ordering::Relaxed),
            tasks_stolen: self.tasks_stolen.load(Ordering::Relaxed),
            tasks_stolen_from: self.tasks_stolen_from.load(Ordering::Relaxed),
            queue_length: self.queue_length(),
            running_count: self.running_count.load(Ordering::Relaxed),
        }
    }
}

/// エグゼキュータ統計
#[derive(Debug, Clone)]
pub struct ExecutorStats {
    /// コアID
    pub core_id: u32,
    /// 実行したタスク数
    pub tasks_executed: u64,
    /// スチールしたタスク数
    pub tasks_stolen: u64,
    /// スチールされたタスク数
    pub tasks_stolen_from: u64,
    /// キューの長さ
    pub queue_length: usize,
    /// 現在実行中のタスク数
    pub running_count: usize,
}

// ============================================================================
// Global Executor Manager
// ============================================================================

/// グローバルエグゼキュータマネージャ
pub struct ExecutorManager {
    /// 全コアのエグゼキュータ
    executors: Mutex<alloc::vec::Vec<Arc<PerCoreExecutor>>>,
    /// コア数
    core_count: AtomicUsize,
    /// グローバルタスクキュー（コア指定なしのspawn用）
    global_queue: Mutex<VecDeque<Arc<Task>>>,
}

impl ExecutorManager {
    /// 新しいマネージャを作成
    pub const fn new() -> Self {
        Self {
            executors: Mutex::new(alloc::vec::Vec::new()),
            core_count: AtomicUsize::new(0),
            global_queue: Mutex::new(VecDeque::new()),
        }
    }
    
    /// エグゼキュータを初期化
    pub fn init(&self, core_count: usize) {
        let mut executors = self.executors.lock();
        executors.clear();
        
        for i in 0..core_count {
            executors.push(Arc::new(PerCoreExecutor::new(i as u32)));
        }
        
        self.core_count.store(core_count, Ordering::Release);
    }
    
    /// 指定コアのエグゼキュータを取得
    pub fn get_executor(&self, core_id: u32) -> Option<Arc<PerCoreExecutor>> {
        let executors = self.executors.lock();
        executors.get(core_id as usize).cloned()
    }
    
    /// 現在のコアのエグゼキュータを取得
    pub fn current_executor(&self) -> Option<Arc<PerCoreExecutor>> {
        let core_id = current_core_id();
        self.get_executor(core_id)
    }
    
    /// タスクをspawn（負荷分散考慮）
    pub fn spawn(&self, task: Arc<Task>) {
        let executors = self.executors.lock();
        
        if executors.is_empty() {
            // エグゼキュータが初期化されていない場合はグローバルキューへ
            drop(executors);
            self.global_queue.lock().push_back(task);
            return;
        }
        
        // 最も負荷の低いエグゼキュータを選択
        let min_executor = executors
            .iter()
            .min_by_key(|e| e.queue_length())
            .cloned();
        
        drop(executors);
        
        if let Some(executor) = min_executor {
            executor.spawn(task);
        }
    }
    
    /// ワークスティーリングを実行
    pub fn try_steal(&self, core_id: u32) -> bool {
        let executors = self.executors.lock();
        
        let thief = match executors.get(core_id as usize) {
            Some(e) => e.clone(),
            None => return false,
        };
        
        // グローバルキューからまず取得
        drop(executors);
        if let Some(task) = self.global_queue.lock().pop_front() {
            thief.spawn(task);
            return true;
        }
        
        let executors = self.executors.lock();
        
        // 最も負荷の高いエグゼキュータからスチール
        let victim = executors
            .iter()
            .filter(|e| e.core_id() != core_id)
            .max_by_key(|e| e.queue_length());
        
        if let Some(victim) = victim {
            if victim.queue_length() > 1 {
                return thief.steal_from(victim).is_some();
            }
        }
        
        false
    }
    
    /// 全エグゼキュータの統計を取得
    pub fn all_stats(&self) -> alloc::vec::Vec<ExecutorStats> {
        self.executors
            .lock()
            .iter()
            .map(|e| e.stats())
            .collect()
    }
    
    /// 全エグゼキュータをシャットダウン
    pub fn shutdown_all(&self) {
        for executor in self.executors.lock().iter() {
            executor.shutdown();
        }
    }
}

// ============================================================================
// Waker Implementation
// ============================================================================

/// タスク用Wakerを作成
fn task_waker(task: Arc<Task>, core_id: u32) -> Waker {
    // ArcをRawPointerに変換
    let task_ptr = Arc::into_raw(task) as *const ();
    let data = TaskWakerData {
        task: task_ptr,
        core_id,
    };
    
    let raw_waker = RawWaker::new(
        Box::into_raw(Box::new(data)) as *const (),
        &WAKER_VTABLE,
    );
    
    unsafe { Waker::from_raw(raw_waker) }
}

/// Wakerのデータ
struct TaskWakerData {
    task: *const (),
    core_id: u32,
}

const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    waker_clone,
    waker_wake,
    waker_wake_by_ref,
    waker_drop,
);

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    let data = &*(data as *const TaskWakerData);
    
    // タスクの参照カウントを増やす
    let task = Arc::from_raw(data.task as *const Task);
    let _ = task.clone();
    core::mem::forget(task);
    
    let new_data = Box::new(TaskWakerData {
        task: data.task,
        core_id: data.core_id,
    });
    
    RawWaker::new(Box::into_raw(new_data) as *const (), &WAKER_VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    waker_wake_by_ref(data);
    waker_drop(data);
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    let data = &*(data as *const TaskWakerData);
    
    // タスクを復元
    let task = Arc::from_raw(data.task as *const Task);
    let task_clone = task.clone();
    core::mem::forget(task); // 参照カウントを維持
    
    // エグゼキュータマネージャにタスクを再スケジュール
    if let Some(executor) = EXECUTOR_MANAGER.get_executor(data.core_id) {
        executor.schedule(task_clone);
    } else {
        // フォールバック: グローバルキューへ
        EXECUTOR_MANAGER.spawn(task_clone);
    }
}

unsafe fn waker_drop(data: *const ()) {
    let data = Box::from_raw(data as *mut TaskWakerData);
    
    // タスクの参照カウントを減らす
    let _ = Arc::from_raw(data.task as *const Task);
}

// ============================================================================
// Global Instance
// ============================================================================

/// グローバルエグゼキュータマネージャ
static EXECUTOR_MANAGER: ExecutorManager = ExecutorManager::new();

/// エグゼキュータマネージャにアクセス
pub fn executor_manager() -> &'static ExecutorManager {
    &EXECUTOR_MANAGER
}

/// エグゼキュータを初期化
pub fn init_executors(core_count: usize) {
    EXECUTOR_MANAGER.init(core_count);
}

/// タスクをspawn（便利関数）
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Task::new(future, Priority::Normal, None);
    EXECUTOR_MANAGER.spawn(task);
}

/// 優先度付きでタスクをspawn
pub fn spawn_with_priority<F>(future: F, priority: Priority, domain_id: Option<u64>)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = Task::new(future, priority, domain_id);
    EXECUTOR_MANAGER.spawn(task);
}

// ============================================================================
// Helper Functions
// ============================================================================

/// TSCを読み取る
#[inline]
fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// 現在のコアIDを取得
#[inline]
fn current_core_id() -> u32 {
    // TODO: 実際のAPIC ID取得に置き換え
    #[cfg(target_arch = "x86_64")]
    {
        // LAPICレジスタからIDを取得する実装
        // 簡易実装: GS baseまたはper-CPU変数から取得
        0
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_task_id_generation() {
        let id1 = TaskId::new();
        let id2 = TaskId::new();
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Realtime < Priority::High);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Normal < Priority::Low);
        assert!(Priority::Low < Priority::Idle);
    }
    
    #[test]
    fn test_executor_creation() {
        let executor = PerCoreExecutor::new(0);
        assert_eq!(executor.core_id(), 0);
        assert_eq!(executor.queue_length(), 0);
    }
}
