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


pub struct Cracker {
    hash_file: File,
    wordlist_file: File,
}

impl Cracker {
    pub fn new(h_file: File, w_file: File) -> Self {
        Cracker {
            hash_file: h_file,
            wordlist_file: w_file
        }
    }

    pub fn run(&self, number_threads: usize) {
        let h_file_clone = match self.hash_file.try_clone() {
            Ok(clone) => clone,
            _ => panic!("Error"),
        };
        let w_file_clone = match self.wordlist_file.try_clone() {
            Ok(clone) => clone,
            _ => panic!("Error"),
        };

        let mut hashes = BufReader::new(h_file_clone).lines();
        let wordlist: Vec<String> = BufReader::new(w_file_clone).lines()
                                    .map(|l| l.expect("Error reading wordlist")).collect();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("passwords.pots")
            .unwrap();

        while let Some(Ok(hash)) = hashes.next() {
            self.crack(&hash, wordlist.clone(), number_threads);
        }
    }

    fn crack(&self, hash: &str, wordlist: Vec<String>, number_threads: usize) {

        let mut pool = make_pool(number_threads).unwrap();

        let arc = Arc::new(Mutex::new(OpenOptions::new()
                                        .write(true)
                                        .create(true)
                                        .open("passwords.pots")
                                        .unwrap()));

        pool.scope(|scope| {
            for chunk in wordlist.chunks(32) {
                let mutex = arc.clone();
                scope.submit(move || {
                    for word in chunk {
                        if unix::verify(word, hash) {
                            let mut file = mutex.lock().unwrap();
                            file.write(word.as_bytes());
                        }
                    }
                });
            }
        });
        //
        // for t in threads {
        //     let mut children = vec![];
        //     for i in base..(base + t) {
        //         let wordlist_data = wordlist_data.clone();
        //         let hash = hash.clone();
        //         children.push(
        //             thread::spawn(move || {
        //                 let ref mut word = wordlist_data.lock().unwrap()[i];
        //                 if unix::verify(word, &hash) {
        //                     Some(word.to_string())
        //                 } else {
        //                     None
        //                 }
        //             })
        //         );
        //     }
        //
        //     for child in children {
        //         match child.join() {
        //             Ok(option) => {
        //                 if option.is_some() {
        //                     return option;
        //                 }
        //             },
        //             _ => ()
        //         }
        //     }
        //
        //     base = base + t;
        //
        // }
        
    }
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//     }
// }
