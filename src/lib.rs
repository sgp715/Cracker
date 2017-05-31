use std::fs::File;
use std::io::{BufRead, BufReader};
use std::thread;
use std::sync::{Arc, Mutex};


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

        while let Some(Ok(hash)) = hashes.next() {
            match self.crack(hash.clone(), wordlist.clone(), number_threads) {
                Some(word) => println!("Successfully Cracked:\n\tpassword: {}\n\thash: {}\n", word, &hash),
                None => println!("Could not crack hash: {}\n", &hash),
            }
        }
    }

    fn crack(&self, hash: String, wordlist: Vec<String>, number_threads: usize) -> Option<String> {

        let number_words = wordlist.len();
        let wordlist_data = Arc::new(Mutex::new(wordlist));
        // let hash_data = Arc::new(hash);
        let mut threads = vec![number_threads; (number_words / number_threads)];
        threads.push(number_words % number_threads);
        let mut base = 0;
        for t in threads {
            let mut children = vec![];
            for i in base..(base + t) {
                let wordlist_data = wordlist_data.clone();
                let hash = hash.clone();
                children.push(
                    thread::spawn(move || {
                        let ref mut word = wordlist_data.lock().unwrap()[i];
                        if unix::verify(word, &hash) {
                            Some(word.to_string())
                        } else {
                            None
                        }
                        // let mut hasher = Blake2b::default();
                        // let ref mut word = wordlist_data.lock().unwrap()[i];
                        // hasher.input(word.to_string().as_bytes());
                        // let hashed_word: Vec<u8> = hasher.result().iter().cloned().collect();
                        // let mut compare = String::new();
                        // for byte in hashed_word {
                        //     compare.push_str(format!("{:x}", byte).as_str());
                        // }
                        // if hash_data.to_lowercase() == compare {
                        //     Some(word.to_string())
                        // } else {
                        //     None
                        // }
                    })
                );
            }

            for child in children {
                match child.join() {
                    Ok(option) => {
                        if option.is_some() {
                            return option;
                        }
                    },
                    _ => ()
                }
            }

            base = base + t;

        }

        None
    }
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//     }
// }
