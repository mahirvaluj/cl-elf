(defsystem "cl-elf"
  :depends-on ()
  :author "seanptmaher@gmail.com"
  :license "MIT"
  :components
  ((:module src
            :serial t
            :components
            ((:file "package")
             (:file "classes")
             (:file "elf")))))
