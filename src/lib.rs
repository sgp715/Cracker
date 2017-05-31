//! # [An API for unix style password cracking](https://github.com/sgp715/Cracker)

use std::fs::File;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::thread;
use std::sync::{Arc, Mutex};

extern crate jobsteal;
use jobsteal::make_pool;

use std::fs::OpenOptions;

extern crate blake2;
use blake2::{Blake2b, Digest};

extern crate pwhash;
use pwhash::unix;

/// The Cracker struct is the main gateway into the cracker API
pub struct Cracker {
    hashes: Vec<String>,
    wordlist: Vec<String>,
    password_pot: String
}

impl Cracker {

    /// Create a new Cracker where
    /// h_file is the hashfile you want to crack,
    bu/// w_file is the wordlist that you want to work with
    /// and p_pot is the password pot that cracked passwords are saved to
    /// # Examples
    /// ```
    /// let cracker = Cracker::new(hash_file, wordlist_file, "password.pot");
    /// ```
    pub fn new(h: Vec<String>, w: Vec<String>, p_pot: String) -> Self {
        Cracker {
            hashes: h,
            wordlist: w,
            password_pot: p_pot,
        }
    }

    /// Runs the cracker that you have created where
    /// number_threads is the number of threads to use
    /// and mangler is the function that you want to mangle words with
    /// # Examples
    /// ```
    /// let cracker = Cracker::new(hash_file, wordlist_file, "password.pot");
    ///
    /// cracker.run(4, some_mangling_function);
    /// ```
    // pub fn run(&self, number_threads: usize, mangler: fn(String) -> Vec<String>) {
        let h_file_clone = match self.hash_file.try_clone() {
            Ok(clone) => clone,
            _ => panic!("Error"),
        };
        let w_file_clone = match self.wordlist_file.try_clone() {
            Ok(clone) => clone,
            _ => panic!("Error"),
        };

        let hashes = BufReader::new(h_file_clone).lines()
                                .map(|l| l.expect("Error reading hashlist")).collect();
        let wordlist: Vec<String> = BufReader::new(w_file_clone).lines()
                                    .map(|l| l.expect("Error reading wordlist")).collect();
    //
    //     let mut file = OpenOptions::new()
    //         .write(true)
    //         .create(true)
    //         .open("passwords.pots")
    //         .unwrap();
    //
    //     self.crack(&hashes, &wordlist, number_threads, &self.password_pot, mangler);
    //
    // }

    pub fn crack(&self, number_threads: usize, password_pot: &str, mangler: fn(String) -> Vec<String>) {

        let mut pool = make_pool(number_threads).unwrap();

        let arc = Arc::new(Mutex::new(OpenOptions::new()
                                        .write(true)
                                        .create(true)
                                        .open(password_pot)
                                        .unwrap()));

            pool.scope(|hash_scope| {
                for hash in &self.hashes {
                    hash_scope.scope(|word_scope| {
                        for chunk in self.wordlist.chunks(number_threads) {
                            let mutex = arc.clone();
                            word_scope.submit(move || {
                                for word in chunk {
                                    let mangled = mangler(word.to_string());
                                    for mangle in &mangled {
                                        if unix::verify(mangle, hash) {
                                            let mut file = mutex.lock().unwrap();
                                            file.write((hash.to_string() + ":" + word + "\n").as_bytes());
                                        }
                                    }
                                }
                            });
                        }
                    });
                }
            });
    }
}
