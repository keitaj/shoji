// Parts shared by shoji's circuits: parsing the signed certificate, and the
// handling of RSA keys and signatures. See ../../src/main.nr (card present) and
// ../../delegated/src/main.nr (delegated).

pub mod cert;
pub mod der;
pub mod keys;
