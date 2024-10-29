//! A crate for applying the AES algorithms individual steps. The crate has not be verified by a security professional and may contain mistakes, use at your own risk. The crate is
//! as such intended to be used for educational purposes.
/// This module contains functions specific to the actual algorithm (Mix Columns, Shift Rows, etc)
pub mod functions {
    
    /// This struct represents a block to be used in the AES Cipher.
    #[derive(Debug, Clone)]
    pub struct Block {
        /// An optional parameter that can be used for keeping track of blocks.
        pub id: usize,
        /// Represents the 16 byte (128 bit) state matrix used in the AES Cipher.
        pub bytes: [u8; 16]
    }

    pub trait AES {
        fn add_round_key(&mut self, key: &Vec<u8>);
        fn mix_columns(&mut self);
        fn shift_rows(&mut self);
        fn sub_bytes(&mut self);
        fn inv_mix_columns(&mut self);
        fn inv_shift_rows(&mut self);
        fn inv_sub_bytes(&mut self);
    }

    impl AES for Block {
        
        /// This function performs the AES Ciphers Add Round Key operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]};
        /// let key: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        /// 
        /// //Apply Add Round Key Operation
        /// block.add_round_key(&key);
        /// 
        /// assert_eq!(block.bytes, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        /// ```
        fn add_round_key(&mut self, key: &Vec<u8>) {
            for (a, b) in self.bytes.iter_mut().zip(key) {
                *a = *a ^ b;
            }
        }

        /// This function performs the AES Ciphers Substitute Bytes operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]};
        /// 
        /// //Apply Substitute Bytes Operation
        /// block.sub_bytes();
        /// 
        /// assert_eq!(block.bytes, [0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63])
        /// ```
        fn sub_bytes(&mut self) {
            for byte in self.bytes.iter_mut() {
                let nibble_a: usize = (*byte >> 4) as usize;
                let nibble_b: usize = (*byte & 0x0f) as usize;
                *byte = S_BOX[nibble_a][nibble_b];
            }
        }
        
        /// This function performs the AES Ciphers Substitute Bytes operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63]};
        /// 
        /// //Apply Inverse Substitute Bytes Operation
        /// block.inv_sub_bytes();
        /// 
        /// assert_eq!(block.bytes, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        /// ```        
        fn inv_sub_bytes(&mut self) {
            for byte in self.bytes.iter_mut() {
                let nibble_a:usize = (*byte >> 4) as usize;
                let nibble_b:usize = (*byte & 0x0f) as usize;
                *byte = INV_S_BOX[nibble_a][nibble_b];
            }
        }
        
        /// This function performs the AES Ciphers Shift Rows operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04]};
        /// 
        /// //Apply Shift Rows Operation
        /// block.shift_rows();
        /// 
        /// assert_eq!(block.bytes, [0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x01, 0x03, 0x04, 0x01, 0x02, 0x04, 0x01, 0x02, 0x03])
        /// ```
        fn shift_rows(&mut self) {
            let mut columns: Vec<Vec<u8>> = self.bytes.chunks(4).map(|x| x.to_owned()).collect();
            
            let mut rows: Vec<Vec<u8>> = vec![columns.iter().map(|x| x[0]).collect(), columns.iter().map(|x| x[1]).collect(), columns.iter().map(|x| x[2]).collect(), columns.iter().map(|x| x[3]).collect()];
            
            for (i, row) in rows.iter_mut().enumerate() {
                row.rotate_left(i);
            }

            columns = vec![rows.iter().map(|x| x[0]).collect(), rows.iter().map(|x| x[1]).collect(), rows.iter().map(|x| x[2]).collect(), rows.iter().map(|x| x[3]).collect()];
            self.bytes = columns.concat().try_into().unwrap();
        }
        
        /// This function performs the AES Ciphers Inverse Shift Rows operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0x01, 0x02, 0x03, 0x04, 0x02, 0x03, 0x04, 0x01, 0x03, 0x04, 0x01, 0x02, 0x04, 0x01, 0x02, 0x03]};
        /// 
        /// //Apply Inverse Shift Rows Operation
        /// block.inv_shift_rows();
        /// 
        /// assert_eq!(block.bytes, [0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04])
        /// ```
        fn inv_shift_rows(&mut self) {
            let mut columns: Vec<Vec<u8>> = self.bytes.chunks(4).map(|x| x.to_owned()).collect();
            
            let mut rows: Vec<Vec<u8>> = vec![columns.iter().map(|x| x[0]).collect(), columns.iter().map(|x| x[1]).collect(), columns.iter().map(|x| x[2]).collect(), columns.iter().map(|x| x[3]).collect()];
            
            for (i, row) in rows.iter_mut().enumerate() {
                row.rotate_right(i);
            }

            columns = vec![rows.iter().map(|x| x[0]).collect(), rows.iter().map(|x| x[1]).collect(), rows.iter().map(|x| x[2]).collect(), rows.iter().map(|x| x[3]).collect()];
            self.bytes = columns.concat().try_into().unwrap();
        }

        /// This function performs the AES Ciphers Mix Columns operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc]};
        /// 
        /// //Apply Inverse Mix Columns Operation
        /// block.mix_columns();
        /// 
        /// assert_eq!(block.bytes, [65, 171, 64, 59, 65, 171, 64, 59, 65, 171, 64, 59, 65, 171, 64, 59])
        /// ```
        fn mix_columns(&mut self) {
            let mut split_data: Vec<Vec<u8>> = self.bytes.chunks(4).map(|x| x.to_owned()).collect();
            let mut mixed_data: Vec<Vec<u8>> = vec![vec![0,0,0,0]; split_data.len()];
            for (i, column) in split_data.iter_mut().enumerate() {
                
                mixed_data[i][0] = g_mul(0x02, column[0]) ^ g_mul(0x03, column[1]) ^ g_mul(0x01, column[2]) ^ g_mul(0x01, column[3]);
                mixed_data[i][1] = g_mul(0x01, column[0]) ^ g_mul(0x02, column[1]) ^ g_mul(0x03, column[2]) ^ g_mul(0x01, column[3]);
                mixed_data[i][2] = g_mul(0x01, column[0]) ^ g_mul(0x01, column[1]) ^ g_mul(0x02, column[2]) ^ g_mul(0x03, column[3]);
                mixed_data[i][3] = g_mul(0x03, column[0]) ^ g_mul(0x01, column[1]) ^ g_mul(0x01, column[2]) ^ g_mul(0x02, column[3]);
            }
        
            self.bytes = mixed_data.concat().try_into().unwrap();
        }
        
        /// This function performs the AES Ciphers Inverse Mix Columns operation on the [Block]s state matrix (4x4, 16 byte matrix).
        /// 
        /// # Examples
        /// 
        /// ```
        /// use aes_edu::functions::{Block, AES};
        /// 
        /// let mut block: Block = Block { id: 0, bytes: [0x41, 0xAB, 0x40, 0x3B, 0x41, 0xAB, 0x40, 0x3B, 0x41, 0xAB, 0x40, 0x3B, 0x41, 0xAB, 0x40, 0x3B]};
        /// 
        /// //Apply Inverse Mix Columns Operation
        /// block.inv_mix_columns();
        /// 
        /// assert_eq!(block.bytes, [0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc])
        /// ```
        fn inv_mix_columns(&mut self) {
            let mut split_data: Vec<Vec<u8>> = self.bytes.chunks(4).map(|x| x.to_owned()).collect();
            let mut mixed_data: Vec<Vec<u8>> = vec![vec![0,0,0,0]; split_data.len()];
            for (i, column) in split_data.iter_mut().enumerate() {
                
                mixed_data[i][0] = g_mul(0x0e, column[0]) ^ g_mul(0x0b, column[1]) ^ g_mul(0x0d, column[2]) ^ g_mul(0x09, column[3]);
                mixed_data[i][1] = g_mul(0x09, column[0]) ^ g_mul(0x0e, column[1]) ^ g_mul(0x0b, column[2]) ^ g_mul(0x0d, column[3]);
                mixed_data[i][2] = g_mul(0x0d, column[0]) ^ g_mul(0x09, column[1]) ^ g_mul(0x0e, column[2]) ^ g_mul(0x0b, column[3]);
                mixed_data[i][3] = g_mul(0x0b, column[0]) ^ g_mul(0x0d, column[1]) ^ g_mul(0x09, column[2]) ^ g_mul(0x0e, column[3]);
            }
        
            self.bytes = mixed_data.concat().try_into().unwrap();
        }
    
    }

    /// This function performs multiplication within Galois Field 256 between 2 bytes.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use aes_edu::functions::g_mul;
    /// 
    /// let byte_a: u8 = 0x56;
    /// let byte_b: u8 = 0xAF;
    /// 
    /// assert_eq!(g_mul(byte_a, byte_b), 0xA9)
    /// ```
    pub fn g_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
    
        for _i in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
    
            let hi_bit_set: bool = (a & 0x80) != 0;
            a <<= 1;
            if hi_bit_set {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    /// The Substitution box for the AES Cipher.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use aes_edu::functions::S_BOX;
    /// 
    /// let byte: u8 = 0x00;
    /// 
    /// let substituted_byte: u8 = S_BOX[0][0];
    /// 
    /// assert_eq!(substituted_byte, 0x63);
    /// ```
    /// 
    pub const S_BOX: [[u8; 16]; 16] = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]];
            
    
    /// The Inverse Substitution box for the AES Cipher.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use aes_edu::functions::INV_S_BOX;
    /// 
    /// let substituted_byte: u8 = 0x63;
    /// 
    /// let byte: u8 = INV_S_BOX[6][3];
    /// 
    /// assert_eq!(byte, 0x00);
    /// ```
    /// 
    pub const INV_S_BOX: [[u8; 16]; 16] = [
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]];
            
}

pub mod key_gen {

    use crate::functions::S_BOX;

    #[derive(Debug, Clone)]
    pub struct Key {
        pub key: [u8;16]
    }

    /// A precomputed array containing the first 11 values for the Round Constant variable. More than 11 are not required to be able to cover AES 128, 192, and 256. <br>
    /// A full table containing 256 values can be found at https://github.com/m3y54m/aes-in-c.
    const RCON: [u8; 11] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c];

    /// This functions implements the AES-256 variant of the AES key schedule. <br>
    /// The input is the 256-bit password to be used.
    /// 
    /// #Examples
    /// 
    /// ```
    /// use aes_edu::key_gen::*;
    /// 
    /// let keys: Vec<Key> = generate_keys_256([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// 
    /// assert_eq!(keys[4].key, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    /// ```
    pub fn generate_keys_256(password: [u8; 32]) -> Vec<Key> {
        let mut current_key: Vec<u8> = password.to_vec();
    
        let mut keys: Vec<Key> = Vec::new();
        for k in 0..8 {
            
            // Push the latest key to the Vector holding all generated keys.
            let left = Key { key: current_key[0..16].try_into().unwrap() };
            let right = Key { key: current_key[16..32].try_into().unwrap() };
            keys.push(left);keys.push(right);
            
            if keys.len() == 16 {
                break;
            }

            // Break the key into 8 columns
            let mut n_key: Vec<Vec<u8>> = current_key.chunks(4).map(|x| x.to_owned()).collect();
            
            // Do initial operations on the last word
            n_key[0] = xor_word(&n_key[0], &rcon(sub_word(rot_word(n_key[7].clone())), k));
    
            // Then use loop to xor the rest
            for i in 1..8 {
                n_key[i] = xor_word(&n_key[i], &n_key[i-1]);
            }
            current_key = n_key.concat();
            println!("{:?}", current_key);
    
    
        }
        
        keys
    }
    
    fn generate_keys_192(password_hash: String) -> Vec<Key> {
        let mut current_key: Vec<u8> = password_hash.into_bytes();
    
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for k in 0..8 {
            
            let mut left = current_key.clone();
            let right = left.split_off(16);
            keys.push(left);keys.push(right);
            
            if keys.len() == 16 {
                break;
            }
    
            //break the key into 8 columns
            let mut n_key: Vec<Vec<u8>> = current_key.chunks(8).map(|x| x.to_owned()).collect();
            
            //do initial xor
            n_key[0] = xor_word(&n_key[0], &rcon(sub_word(rot_word(n_key[7].clone())), k));
    
            //then use loop to do the rest
            for i in 1..8 {
                n_key[i] = xor_word(&n_key[i], &n_key[i-1]);
            }
            current_key = n_key.concat();
    
    
        }
        todo!();
        //keys
    }
    fn generate_keys_128(password_hash: String) -> Vec<Key> {
        let mut current_key: Vec<u8> = password_hash.into_bytes();
    
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for k in 0..8 {
            
            let mut left = current_key.clone();
            let right = left.split_off(16);
            keys.push(left);keys.push(right);
            
            if keys.len() == 16 {
                break;
            }
    
            //break the key into 8 columns
            let mut n_key: Vec<Vec<u8>> = current_key.chunks(8).map(|x| x.to_owned()).collect();
            
            //do initial xor
            n_key[0] = xor_word(&n_key[0], &rcon(sub_word(rot_word(n_key[7].clone())), k));
    
            //then use loop to do the rest
            for i in 1..8 {
                n_key[i] = xor_word(&n_key[i], &n_key[i-1]);
            }
            current_key = n_key.concat();
    
    
        }
        todo!();
        //keys
    }
    
    fn rot_word(mut word: Vec<u8>) -> Vec<u8> {
        word.rotate_left(1);
        word
    }
    
    fn sub_word(mut word: Vec<u8>) -> Vec<u8> {
    
        for byte in word.iter_mut() {
            let nibble_a:usize = (*byte >> 4) as usize;
            let nibble_b:usize = (*byte & 0x0f) as usize;
            *byte = S_BOX[nibble_a][nibble_b].clone();
        }
        word
    }
    
    fn rcon(word: Vec<u8>, iteration: usize) -> Vec<u8> {
        xor_word(&word, &vec![RCON[iteration], 0x00, 0x00, 0x00])
    }
    
    fn xor_word(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
        let mut xor_result: Vec<u8> = Vec::with_capacity(8);
        for (c, d) in a.iter().zip(b) {
            xor_result.push(c^d);
        }
        xor_result
    }

}