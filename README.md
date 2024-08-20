## A Tool for Mirroring Packets to a Target Server

## Quick Start
* [Download the latest mirror release](https://github.com/session-replay-tools/mirror/releases).
* Clone the repo: `git clone git://github.com/session-replay-tools/mirror.git`.

## Installing `mirror`
1. Navigate to the `mirror` directory:
   
   `cd mirror`

2. Run the configuration script:
   
   `./configure`

   Optionally, specify any necessary configuration options.

3. Compile the program:
   
   `make`

4. Install the compiled program:
   
   `make install`



### Configure Options for `mirror`
     --with-pfring=PATH  Set the path to PF_RING library sources  
     --with-debug        Compile mirror with debug support (saved in a log file)

## Running 

`./mirror -s sourceMacAddress -t targetMacAddress -F <filter> -o <device> -i <device> -x destIPAddress -d`

see -h for more details

## Note
1. Root privilege or the CAP_NET_RAW capability(e.g. setcap CAP_NET_RAW=ep mirror) is required 

## Release History
+ 2014.09  v1.0    `mirror` released
+ 2024.09  v1.0    Document normalization


## Bugs and Feature Requests
Have a bug or a feature request? [Please open a new issue](https://github.com/session-replay-tools/mirror/issues). Before opening any issue, please search for existing issues.


## Copyright and License

Copyright 2024 under [the BSD license](LICENSE).
