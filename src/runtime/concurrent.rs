use std::{
    future::{poll_fn, Future},
    pin::Pin,
    task::Poll,
};

pub(crate) struct BoundedUnordered<F> {
    futures: Vec<Pin<Box<F>>>,
}

impl<F> Default for BoundedUnordered<F> {
    fn default() -> Self {
        Self {
            futures: Vec::new(),
        }
    }
}

impl<F: Future> BoundedUnordered<F> {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        self.futures.len()
    }

    pub(crate) fn push(&mut self, future: F) {
        self.futures.push(Box::pin(future));
    }

    pub(crate) async fn next(&mut self) -> Option<F::Output> {
        poll_fn(|cx| {
            let mut idx = 0;
            while idx < self.futures.len() {
                match self.futures[idx].as_mut().poll(cx) {
                    Poll::Ready(output) => {
                        drop(self.futures.swap_remove(idx));
                        return Poll::Ready(Some(output));
                    }
                    Poll::Pending => idx += 1,
                }
            }

            if self.futures.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

pub(crate) async fn bounded_map<I, T, F, Fut, O>(items: I, limit: usize, mut f: F) -> Vec<O>
where
    I: IntoIterator<Item = T>,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = O>,
{
    let mut items = items.into_iter();
    let limit = limit.max(1);
    let mut pending = BoundedUnordered::new();
    let mut out = Vec::new();

    while pending.len() < limit {
        let Some(item) = items.next() else {
            break;
        };
        pending.push(f(item));
    }

    while let Some(output) = pending.next().await {
        out.push(output);
        if let Some(item) = items.next() {
            pending.push(f(item));
        }
    }

    out
}
