use crate::runtime::bytes::HiBytes;
use std::io::{self, IoSlice};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::client::TlsStream;

pub(crate) async fn write_h2(
    mut writer: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    mut rx: mpsc::UnboundedReceiver<Vec<HiBytes>>,
) {
    let mut pending = Vec::new();
    while let Some(frames) = rx.recv().await {
        pending.extend(frames);
        while let Ok(frames) = rx.try_recv() {
            pending.extend(frames);
        }
        if write_vectored_all(&mut writer, &pending).await.is_err() {
            break;
        }
        pending.clear();
    }
}

async fn write_vectored_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frames: &[HiBytes],
) -> io::Result<()> {
    let mut frame_index = 0usize;
    let mut offset = 0usize;
    while frame_index < frames.len() {
        let ios: Vec<IoSlice<'_>> = frames[frame_index..]
            .iter()
            .take(64)
            .enumerate()
            .map(|(idx, frame)| {
                if idx == 0 {
                    IoSlice::new(&frame[offset..])
                } else {
                    IoSlice::new(frame)
                }
            })
            .collect();
        let mut written = writer.write_vectored(&ios).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        while frame_index < frames.len() {
            let remaining = frames[frame_index].len() - offset;
            if written < remaining {
                offset += written;
                break;
            }
            written -= remaining;
            frame_index += 1;
            offset = 0;
            if written == 0 {
                break;
            }
        }
    }
    writer.flush().await
}
