use protocol::{Parcel, Error, Settings};

pub trait ParcelExt<T> {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<T, Error>;
}

impl<T: Parcel> ParcelExt<T> for T {
    fn to_bytes(&self) -> Vec<u8> {
        self.raw_bytes(&Settings::default()).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<T, Error> {
        T::from_raw_bytes(
            bytes,
            &Settings::default()
        )
    }
}
