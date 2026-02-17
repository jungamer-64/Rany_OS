use super::*;

#[test_case]
fn test_ring_buffer() {
    let mut buf = RingBuffer::new(16);

    assert!(buf.is_empty());
    assert!(!buf.is_full());

    let written = buf.write(b"Hello");
    assert_eq!(written, 5);
    assert_eq!(buf.len(), 5);

    let mut read_buf = [0u8; 10];
    let read = buf.read(&mut read_buf);
    assert_eq!(read, 5);
    assert_eq!(&read_buf[..5], b"Hello");
}

#[test_case]
fn test_pipe_sync() {
    let pipe = pipe();

    let written = pipe.writer.write_sync(b"Test data").unwrap();
    assert!(written > 0);

    let mut buf = [0u8; 32];
    let read = pipe.reader.read_sync(&mut buf).unwrap();
    assert_eq!(read, written);
}

#[test_case]
fn test_zero_copy_channel() {
    let domain1 = DomainId::new(1);
    let domain2 = DomainId::new(2);

    let (sender, receiver) = zero_copy_channel::<u32>(16, domain1, domain2);

    // 送信
    sender.send(42).unwrap();

    // 受信
    let rref = receiver.recv().unwrap();
    assert_eq!(*rref, 42);
    assert_eq!(rref.owner(), domain2); // 所有権が移動している
}
