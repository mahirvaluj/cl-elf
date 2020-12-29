(in-package :elf)

(defun read-bytes-with-endian (s size endianness)
  "read `size` bytes from `s` and treat as `endianness` (:big or :little)"
  (let ((input (loop for i from 0 below size collect (read-byte s))))
    (cond
      ((eq endianness :big)
       (let ((acc 0))
         (loop with byte = size for i in input
            do (setf acc (logior acc (ash i (* 8 (- byte 1))))
                     byte (- byte 1)))
         acc))
      ((eq endianness :little)
       (let ((acc 0))
         (loop with byte = 0 for i in input
            do (setf acc (logior acc (ash i (* 8 byte)))
                     byte (+ byte 1)))
         acc))
      (t (error (format nil "Unknown endianness ~A" endianness))))))

(defun parse-all-headers (filespec)
  (let ((elf (make-instance 'elf)))
    (with-open-file (s filespec :element-type '(unsigned-byte 8))
      (setf (ehead elf) (parse-elf-header s))
      (file-position s (program-header-offset (ehead elf)))
      (setf (p-head-entries elf) (loop for i from 0 below (p-head-num-entries (ehead elf))
                                    collect (parse-prog-header-entry s (ehead elf))))
      (file-position s (section-header-offset (ehead elf)))
      (setf (s-head-entries elf) (loop for i from 0 below (s-head-num-entries (ehead elf))
                                    collect (parse-sect-header-entry s (ehead elf))))
      (file-position s 0)
      (setf (filebuf elf)
            (let ((seq (make-array (file-length s) :element-type '(unsigned-byte 8))))
              (read-sequence seq s)
              seq)))
    elf))

(defmethod parse-elf-header ((s stream))
  "Parses elf file header from stream, returns 'elf-header' object"
  (let ((elf-header (make-instance 'elf-header)))
    ;; eat magic bytes
    (loop for i from 1 to 4 do (read-byte s))
    ;; word-size
    (setf (cpu-word-width elf-header) (case (read-byte s) (1 :32)     (2 :64))
          (endianness elf-header)     (case (read-byte s) (1 :little) (2 :big)))
    ;; set to 1 for the current version of ELF
    (assert (= 1 (read-byte s)))
    (setf (os-abi elf-header) (case (read-byte s)
                                (0 :system-v)
                                (1 :hp-ux)
                                (2 :netbsd)
                                (3 :linux)
                                (4 :gnu-hurd)
                                (6 :solaris)
                                (7 :aix)
                                (8 :irix)
                                (9 :freebsd)
                                (10 :tru64)
                                (11 :novell-modesto)
                                (12 :openbsd)
                                (13 :openvms)
                                (14 :nonstop-kernel)
                                (15 :aros)
                                (16 :fenix-os)
                                (17 :cloudabi)
                                (18 :stratus-openvos))
          (abi-version elf-header) (read-byte s))
    ;; eat padding
    (loop for i from 0 below 7 do (read-byte s))
    ;; from now on, multibyte entries require reading with endinanness
    
    ;; note: file-type has a bunch of reserved bytes so I don't parse
    ;; it into keywords here
    (setf (file-type elf-header) (read-bytes-with-endian s 2 (end elf-header))
          (isa elf-header)       (case (read-bytes-with-endian s 2 (end elf-header))
                                   (0 :none)
                                   (1 :at&t-we-32100)
                                   (2 :sparc)
                                   (3 :x86)
                                   (4 :m68k)
                                   (5 :m88k)
                                   (6 :intel-mcu)
                                   (7 :intel-80860)
                                   (8 :mips)
                                   (9 :ibm-system-370)
                                   (#x0a :mips-rs3000-le)
                                   (#x0e :hp-pa-risc)
                                   (#x13 :intel-809060)
                                   (#x14 :powerpc)
                                   (#x15 :powerpc-64bit)
                                   (#x16 :s390)
                                   (#x28 :arm)
                                   (#x2a :superh)
                                   (#x32 :ia-64)
                                   (#x3e :amd64)
                                   (#x8c :tms320c6000)
                                   (#xb7 :arm64)
                                   (#xf3 :risc-v)
                                   (#x101 :wdc-65c816)))
    ;; eat 4 bytes for elf version
    (assert (= 1 (read-bytes-with-endian s 4 (end elf-header))))
    ;; read either 4 or 8 bytes depending on whether we're 32-bit or
    ;; 64-bit wide for the addresses
    (setf
     (entry-point elf-header)           (read-bytes-with-endian s
                                                                (cond ((eq :32 (cpu-word-width elf-header)) 4)
                                                                      ((eq :64 (cpu-word-width elf-header)) 8))
                                                                (end elf-header))
     (program-header-offset elf-header) (read-bytes-with-endian s
                                                                (cond ((eq :32 (cpu-word-width elf-header)) 4)
                                                                      ((eq :64 (cpu-word-width elf-header)) 8))
                                                                (end elf-header))
     (section-header-offset elf-header) (read-bytes-with-endian s
                                                                (cond ((eq :32 (cpu-word-width elf-header)) 4)
                                                                      ((eq :64 (cpu-word-width elf-header)) 8))
                                                                (end elf-header)))
    ;; architecture-specific-flags, followed by sizes of headsers
    (setf (flags              elf-header) (read-bytes-with-endian s 4 (end elf-header))
          (e-head-size        elf-header) (read-bytes-with-endian s 2 (end elf-header))
          (p-head-entry-size  elf-header) (read-bytes-with-endian s 2 (end elf-header))
          (p-head-num-entries elf-header) (read-bytes-with-endian s 2 (end elf-header))
          (s-head-entry-size  elf-header) (read-bytes-with-endian s 2 (end elf-header))
          (s-head-num-entries elf-header) (read-bytes-with-endian s 2 (end elf-header))
          (section-name-index elf-header) (read-bytes-with-endian s 2 (end elf-header)))
    elf-header))

(defmethod parse-prog-header-entry ((s stream) (ehead elf-header))
  "Parses program header entry from stream, returns 'program-header-entry'"
  (let ((phead (make-instance 'program-header-entry)))
    ;; todo: extra info here, maybe convert to keywords
    (setf (entry-type phead) (read-bytes-with-endian s 4 (end ehead)))
    ;; this is where flags are at on 64-bit machines
    (when (eq (cpu-word-width ehead) :64)
      (setf (flags phead) (read-bytes-with-endian s 4 (end ehead))))
    ;; a bunch of offsets and sizes
    (let ((natural-width (cond ((eq :32 (cpu-word-width ehead)) 4)
                               ((eq :64 (cpu-word-width ehead)) 8))))
      (setf
       (offset         phead) (read-bytes-with-endian s natural-width (end ehead))
       (virt-address   phead) (read-bytes-with-endian s natural-width (end ehead))
       (phys-address   phead) (read-bytes-with-endian s natural-width (end ehead))
       (size-in-file   phead) (read-bytes-with-endian s natural-width (end ehead))
       (size-in-memory phead) (read-bytes-with-endian s natural-width (end ehead))))
    ;; on 32-bit machines, the flags are here
    (when (eq (cpu-word-width ehead) :32)
      (setf (flags phead) (read-bytes-with-endian s 4 (end ehead))))
    ;; alignment -- 0, 1 -> no alignment | positive power of 2 -> alignment
    ;; note: (virtual addr = offset (% alignment))
    (setf (alignment phead) (read-bytes-with-endian s (cond ((eq :32 (cpu-word-width ehead)) 4)
                                                            ((eq :64 (cpu-word-width ehead)) 8))
                                                    (end ehead)))
    phead))
              
(defmethod parse-sect-header-entry ((s stream) (ehead elf-header))
  "Parses sectiion header entry from stream, returns 'section-header-entry'"
  (let ((shead (make-instance 'section-header-entry))
        (natural-width (cond ((eq :32 (cpu-word-width ehead)) 4)
                             ((eq :64 (cpu-word-width ehead)) 8))))
    (setf (name-index shead) (read-bytes-with-endian s 4 (end ehead)))
    (let ((entry-type (read-bytes-with-endian s 4 (end ehead))))
      (setf (entry-type shead) (case entry-type
                                 (#x0 `(:null #x0)) ;; Section header table entry unused
                                 (#x1 `(:progbits #x1)) ;; Program data
                                 (#x2 `(:symtab #x2)) ;; Symbol table
                                 (#x3 `(:strtab #x3)) ;; String table
                                 (#x4 `(:rela #x4)) ;; Relocation entries with addends
                                 (#x5 `(:hash #x5)) ;; Symbol hash table
                                 (#x6 `(:dynamic #x6)) ;; Dynamic linking information
                                 (#x7 `(:note #x7))    ;; Notes
                                 (#x8 `(:nobits #x8)) ;; Program space with no data (bss)
                                 (#x9 `(:rel #x9)) ;; Relocation entries, no addends
                                 (#x0A `(:shlib #x0a)) ;; Reserved
                                 (#x0B `(:dynsym #x0b)) ;; Dynamic linker symbol table
                                 (#x0E `(:init_array #x0E)) ;; Array of constructors
                                 (#x0F `(:fini_array #x0F)) ;; Array of destructors
                                 (#x10 `(:preinit_array #x10)) ;; Array of pre-constructors
                                 (#x11 `(:group #x11)) ;; Section group
                                 (#x12 `(:symtab_shndx #x12)) ;; Extended section indices
                                 (#x13 `(:num #x13)) ;; Number of defined types.
                                 (t (if (>= entry-type #x60000000)
                                        `(:os-specific ,entry-type)
                                        (error "unknown entry-type")))))) 
    ;; these are the section flags, which indicate the memory attributes
    (let ((acc nil)
          (fval (read-bytes-with-endian s natural-width (end ehead))))
      (when (not (= 0 (logand #x1        fval))) (push :WRITE acc)) ;; Writable
      (when (not (= 0 (logand #x2        fval))) (push :ALLOC acc)) ;; Occupies memory during execution
      (when (not (= 0 (logand #x4        fval))) (push :EXECINSTR acc)) ;; Executable
      (when (not (= 0 (logand #x10       fval))) (push :MERGE acc)) ;; Might be merged
      (when (not (= 0 (logand #x20       fval))) (push :STRINGS acc)) ;; Contains null-terminated strings
      (when (not (= 0 (logand #x40       fval))) (push :INFO_LINK acc)) ;; 'sh_info' contains SHT index
      (when (not (= 0 (logand #x80       fval))) (push :LINK_ORDER acc)) ;; Preserve order after combining
      (when (not (= 0 (logand #x100      fval))) (push :OS_NONCONFORMING acc)) ;; Non-standard OS specific handling required
      (when (not (= 0 (logand #x200      fval))) (push :GROUP acc)) ;; Section is member of a group
      (when (not (= 0 (logand #x400      fval))) (push :TLS acc)) ;; Section hold thread-local data
      (when (not (= 0 (logand #x0ff00000 fval))) (push :MASKOS acc)) ;; OS-specific
      (when (not (= 0 (logand #xf0000000 fval))) (push :MASKPROC acc)) ;; Processor-specific
      (when (not (= 0 (logand #x4000000  fval))) (push :ORDERED acc)) ;; Special ordering requirement (Solaris)
      (when (not (= 0 (logand #x8000000  fval))) (push :EXCLUDE acc)) ;; Section is excluded unless referenced or allocated (Solaris)
      (setf (flags shead) `(,acc ,fval)))
    ;; where to find/put/load the section
    (setf (virt-address   shead) (read-bytes-with-endian s natural-width (end ehead))
          (offset-in-file shead) (read-bytes-with-endian s natural-width (end ehead))
          (size-in-file   shead) (read-bytes-with-endian s natural-width (end ehead))
          (link-index     shead) (read-bytes-with-endian s 4 (end ehead))
          (info           shead) (read-bytes-with-endian s 4 (end ehead))
          (alignment      shead) (read-bytes-with-endian s natural-width (end ehead))
          (ent-size       shead) (read-bytes-with-endian s natural-width (end ehead)))
    shead))

