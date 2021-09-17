
use crate::elf::sym::Sym;
use crate::elf::sym::STB_GLOBAL;
use crate::elf::sym::STB_WEAK;
use crate::elf::section_header::SHN_UNDEF;
use crate::strtab::Strtab;
use crate::elf::sym::Symtab;
use crate::elf::Elf;
use core::fmt;
use core::mem;
use core::slice;


/// ELF hash function: accepts a symbol name and returns a value that may be
/// used to compute a bucket index.
///
/// Consequently, if the hashing function returns the value `x` for some name,
/// `buckets[x % nbuckets]` gives an index, `y`, into both the symbol table
/// and the chain table.
pub fn hash(symbol: &str) -> u32 {
    symbol.bytes().fold(0,|mut hash,b|{
        hash = (hash << 4) + b as u32;
		let g = hash & 0xf0000000;
		hash=(hash^g) ^(g >> 24);
        hash
    })
}

mod tests {
    use super::hash;
    #[test]
    fn test_hash() {
        assert_eq!(hash(""), 0);
        assert_eq!(hash("printf"), 125371814);
        assert_eq!(hash("exit"), 446212);
        assert_eq!(hash("syscall"), 185178204);
        assert_eq!(hash("flapenguin.me"), 60324117);
    }
}

const INT_SIZE: usize = mem::size_of::<u32>();
const U32_SIZE: usize = mem::size_of::<u32>();

/// A better hash table for the ELF used by GNU systems in GNU-compatible software.
pub struct ElfHash<'a> {
    /// length of the bucket
    nbucket:u32,
    /// length of the chain
    nchain:u32,
    /// elf hash table bucket array; indexes start at 0. This array holds symbol
    /// table indexes and contains the index of hashes in `chains`
    buckets:&'a [u32],// => bucket[nbucket]
    /// Hash values; indexes start at 0. This array holds symbol table indexes.
    chains:&'a [u32], // => chains[nchain]
    dynsyms: &'a Symtab<'a>,
    dynstrtab: &'a Strtab<'a>
}


impl fmt::Debug for ElfHash<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ElfHash")
            .field("nbucket", &self.nbucket)
            .field("nchain", &self.nchain)
            .field("bucket", &self.buckets.as_ptr())
            .field("chains", &self.chains.as_ptr())
            .finish()
    }
}

impl<'a> ElfHash<'a> {
    /// Initialize a ElfHash from a pointer to `.hash` section
    /// and total number of dynamic symbols.
    /// # Safety
    ///
    /// This function creates a `ElfHash` directly from a raw pointer
    pub unsafe fn from_raw_table(
        hashtab: &'a [u8],
        dynsyms: &'a Symtab<'a>,
        dynstrtab: &'a Strtab<'a>
    ) -> Result<Self, &'static str> {
        if hashtab.as_ptr() as usize % INT_SIZE != 0 {
            return Err("hashtab is not aligned with 32-bit");
        }

        if hashtab.len() <= 8 {
            return Err("failed to read in number of buckets");
        }

        let [nbucket, nchain] =
            (hashtab.as_ptr() as *const u32 as *const [u32; 2]).read();

        let hashtab = &hashtab[8..];
        // SAFETY: Condition to check for an overflow
        //   size_of(chains) + size_of(buckets) + size_of(bloom_filter) == size_of(hashtab)
        let buckets_ptr=hashtab.as_ptr() as *const u32;
        let buckets:&[u32] = slice::from_raw_parts(buckets_ptr, nbucket as usize);
        let chain_ptr=buckets_ptr.add(nbucket as usize);
        let chains = slice::from_raw_parts(chain_ptr, nchain as usize);
        Ok(Self {
            nbucket,
            nchain,
            buckets,
            chains,
            dynsyms,
            dynstrtab
        })
    }

    pub fn from_elf(elf:&'a Elf,bytes:&'a [u8])-> ElfHash<'a>{
        let dynamic=elf.dynamic.as_ref().unwrap();
        let hash_offset=dynamic.info.hash.unwrap() as usize;
        unsafe{Self::from_raw_table(&bytes[hash_offset..], &elf.dynsyms,&elf.dynstrtab).unwrap()}
    }

    /// Locate the hash chain, and corresponding hash value element.
    #[cold]
    fn lookup(&'a self, symbol_name: &str, hash: u32) -> Option<Sym> {
        let mut symbol_index=self.buckets[(hash%self.nbucket)as usize] as usize;
        while symbol_index!=0{
            let symbol=self.dynsyms.get(symbol_index).unwrap();
            symbol_index=self.chains[symbol_index] as usize;
            let cur_symbol_name=&self.dynstrtab[symbol.st_name];
            if symbol_name==cur_symbol_name{
                if symbol.st_bind()==STB_GLOBAL || symbol.st_bind()==STB_WEAK{
                    if symbol.st_shndx == SHN_UNDEF as usize {
                        continue;
                    }
                    return Some(symbol);
                }
            }
        }
        return None;
    }

    /// Given a symbol, a hash of that symbol, a dynamic string table and
    /// a `dynstrtab` to cross-reference names, maybe returns a Sym.
    pub fn find_with_symbol_name(&'a self, symbol: &str) -> Option<Sym> {
        let hash = self::hash(symbol);
        self.lookup(symbol, hash)
    }


    /// find the best bucket to create a elf hash table
    pub fn find_best_bucket(sym_count:u32) -> u32{
        let elf_buckets = [
            1, 3, 17, 37, 67, 97, 131, 197, 263, 521, 1031, 2053, 4099, 8209,
            16411, 32771
        ];
        for i in 0..elf_buckets.len()-1{
            if sym_count < elf_buckets[i+1]{
                return elf_buckets[i];
            }
        }
        return elf_buckets.last().unwrap().to_owned();
    }
}