use futures::io::{AsyncReadExt, AsyncWriteExt};
use protocol::{Error, Parcel, Settings};

pub trait ParcelExt<T> {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<T, Error>;
}

impl<T: Parcel> ParcelExt<T> for T {
    fn to_bytes(&self) -> Vec<u8> {
        self.raw_bytes(&Settings::default()).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<T, Error> {
        T::from_raw_bytes(bytes, &Settings::default())
    }
}

pub trait Stream: AsyncReadExt + AsyncWriteExt + Unpin {}

impl<T: AsyncReadExt + AsyncWriteExt + Unpin> Stream for T {}

#[derive(Debug, PartialEq)]
pub struct StreamWrapper<T: Stream>(pub T);

impl<T: Stream> StreamWrapper<T> {
    pub fn new(stream: T) -> Self {
        Self(stream)
    }
    pub async fn send(&mut self, item: impl Parcel) -> Result<(), futures::io::Error> {
        let data = item.to_bytes();
        let data_len = data.len().to_le_bytes();
        await!(self.0.write_all(&data_len))?;
        await!(self.0.write_all(&data))?;
        Ok(())
    }
}
