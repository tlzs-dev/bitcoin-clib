A bitcoin library in C
======================

License
-------
[The MIT License (MIT)](https://opensource.org/licenses/MIT)


Dependencies
-------------

These dependencies are required:

    ----------------------------------------
    Library         |  Description
    ----------------|-----------------------
    libdb-5.3       | blocks.db and utxoes.db
    libsecp256k1    | crypto: sign / verify
    libgmp          | uint256 Arithmetic
    ----------------------------------------

Optional dependencies:

    ----------------------------------------
    Library         |  Description
    ----------------|-----------------------
    gtk+-3.0        | GUI
    libsoup-2.4     | JSON-RPC HTTP server
    json-c          | json 
    ----------------------------------------


## Build

### Linux / Debian 

#### install dependencies

    $ sudo apt-get install build-essential libgmp-dev libdb5.3-dev 
    
    $ cd /tmp && git clone https://github.com/bitcoin-core/secp256k1
    $ cd secp256k1 && ./autogen.sh
    $ ./configure
    $ make && sudo make install
    
    (optional)
    $ sudo apt-get install libgtk-3-dev libjson-c-dev libsoup2.4-dev

#### build

    $ git clone https://github.com/chehw/bitcoin-clib
    $ cd bitcoin-clib
    $ make
    
    (optional: build test modules)
    $ cd tests && make
    $ cd test2 && make
    $ cd test3 && make
    
