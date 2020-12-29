(in-package :elf)

(defclass elf ()
  ((elf-header :accessor ehead)
   (program-header-entries :accessor p-head-entries)
   (section-header-entries :accessor s-head-entries)
   (sections :accessor sections)))

(defclass elf-header ()
  ((cpu-word-width ;; :32 or :64
    :initarg :cpu-word-width :accessor cpu-word-width)
   (endianness ;; :big or :little
    :initarg :endianness :accessor end :accessor endianness)
   (os-abi ;; linux, sys V, bsd, etc
    :initarg :os-abi :accessor os-abi)
   (abi-version
    :initarg :abi-version :accessor abi-version) 
   (file-type
    :initarg :file-type :accessor file-type)
   (isa ;; actual architecture
    :initarg :isa :accessor isa)
   (entry-point 
    :initarg :entry-point :accessor entry-point)
   (program-header-offset 
    :initarg :program-header-offset :accessor program-header-offset)
   (section-header-offset 
    :initarg :section-header-offset :accessor section-header-offset)
   (flags 
    :initarg :flags :accessor flags)
   (e-head-size 
    :initarg :e-head-size :accessor e-head-size)
   (p-head-entry-size 
    :initarg :p-head-entry-size :accessor p-head-entry-size)
   (p-head-num-entries 
    :initarg :p-head-num-entries :accessor p-head-num-entries)
   (s-head-entry-size 
    :initarg :s-head-entry-size :accessor s-head-entry-size)
   (s-head-num-entries 
    :initarg :s-head-num-entries :accessor s-head-num-entries)
   (section-name-index
    :initarg :section-name-index :accessor section-name-index)))

(defclass program-header-entry ()
  ((entry-type
    :initarg :entry-type :accessor entry-type)
   (flags
    :initarg :flags :accessor flags)
   (offset
    :initarg :offset :accessor offset)
   (virt-address
    :initarg :virt-address :accessor virt-address)
   (phys-address
    :initarg :phys-address :accessor phys-address)
   (size-in-file ;; in bytes
    :initarg :size-in-file :accessor size-in-file)
   (size-in-memory ;; in bytes
    :initarg :size-in-memory :accessor size-in-memory)
   (alignment ;; 0,1 -> no alignment | positive power of 2
    :initarg :alignment :accessor alignment)))

(defclass section-header-entry ()
  ((name-index ;; offset into .shstrtab 
    :initarg :name-index :accessor name-index)
   (entry-type
    :initarg :entry-type :accessor entry-type) 
   (flags
    :initarg :flags :accessor flags)
   (virt-address
    :initarg :virt-address :accessor virt-address)
   (offset-in-file
    :initarg :offset-in-file :accessor offset-in-file)
   (size-in-file
    :initarg :size-in-file :accessor size-in-file)
   (link-index ;; may contain link to another section
    :initarg :link-index :accessor link-index)
   (info ;; used for many things
    :initarg :info :accessor info)
   (alignment ;; power of 2
    :initarg :alignment :accessor alignment)
   (ent-size
    :initarg :ent-size :accessor ent-size)))
